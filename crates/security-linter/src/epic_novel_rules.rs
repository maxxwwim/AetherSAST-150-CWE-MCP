use crate::lexer::{self, Lang};
use crate::linter::{CveRuleDef, LinterViolation};

/// Règles sémantiques inédites (hors taxonomie CWE classique) & détecteurs de portes dérobées invisibles.
pub struct EpicNovelRules;

impl EpicNovelRules {
    pub fn definitions() -> Vec<CveRuleDef> {
        vec![
            CveRuleDef {
                rule_id: "AETHER-RUST-ASYNC-TLS-BLEED".to_string(),
                cve_id: "AETHER-EXEC-001 / ASYNC-WORKSTEAL-TLS-CONTAMINATION".to_string(),
                name: "Rust Async: Contamination Inter-Tâches via thread_local! à Travers .await".to_string(),
                category: "Rust / Async & Type Soundness".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Mutation ou lecture d'un thread_local! dans une async fn contenant un point de suspension .await sans tokio::task_local! : l'ordonnanceur work-stealing peut reprendre la tâche d'un autre tenant/utilisateur sur le même thread OS avec l'état de sécurité précédent encore actif.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-SERDE-INVARIANT-ERASURE".to_string(),
                cve_id: "AETHER-TYPE-002 / SERDE-CONSTRUCTOR-INVARIANT-BYPASS".to_string(),
                name: "Rust Type Soundness: Érosion de Smart Constructor par #[derive(Deserialize)]".to_string(),
                category: "Rust / Async & Type Soundness".to_string(),
                severity: "HIGH".to_string(),
                description: "Structure Rust à champs privés protégeant des invariants via un constructeur faillible (new/try_new -> Result/Option) tout en dérivant #[derive(Deserialize)] ou BorshDeserialize sans #[serde(try_from = ...)] ni implémentation manuelle : permet d'instancier un état invalide directement depuis le réseau.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-ASYNC-FRAME-SECRET-RESIDENCY".to_string(),
                cve_id: "AETHER-COMP-003 / COROUTINE-FRAME-SECRET-GHOSTING".to_string(),
                name: "Rust Compiler: Persistance de Secret dans une Frame Async à Travers .await".to_string(),
                category: "Rust / Async & Type Soundness".to_string(),
                severity: "HIGH".to_string(),
                description: "Matériel cryptographique ou secret (Zeroizing, SigningKey, PrivateKey) conservé dans une async fn à travers un point .await sans Box<Zeroizing<T>> ni drop préalable : la machine à états générée par rustc copie les octets entre variantes sur le tas sans effacer les copies intermédiaires.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-PERSISTENT-WORKER-BLEED".to_string(),
                cve_id: "AETHER-EXEC-004 / SHARED-NOTHING-RUNTIME-VIOLATION".to_string(),
                name: "PHP Worker: Contamination d'État Inter-Requêtes (Octane / FrankenPHP / Swoole)".to_string(),
                category: "PHP / Runtime & Control-Flow".to_string(),
                severity: "CRITICAL".to_string(),
                description: "État utilisateur, identité ou cache mutable conservé en variable static / propriété statique / $GLOBALS dans un runtime PHP persistant longue durée sans ResetInterface ni purge inter-requêtes : fuite de session ou de tenant entre requêtes HTTP consécutives.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-GENERATOR-DEFERRED-GUARD".to_string(),
                cve_id: "AETHER-CTRL-005 / LAZY-YIELD-AUTH-BYPASS".to_string(),
                name: "PHP Control-Flow: Effacement Paresseux de Garde de Sécurité par yield (Generator)".to_string(),
                category: "PHP / Runtime & Control-Flow".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Présence d'un garde d'autorisation ou validation (throw/abort/isAdmin) dans une fonction PHP contenant yield : PHP transforme silencieusement toute la fonction en Generator paresseux dont aucune ligne ne s'exécute à l'appel.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-PCRE-BACKTRACK-FAILOPEN".to_string(),
                cve_id: "AETHER-CTRL-006 / PCRE-LIMIT-SILENT-FAIL-OPEN".to_string(),
                name: "PHP PCRE: Contournement Silencieux Fail-Open via pcre.backtrack_limit".to_string(),
                category: "PHP / Runtime & Control-Flow".to_string(),
                severity: "HIGH".to_string(),
                description: "Garde négatif !preg_match() ou preg_match() == 0 sans vérification === false / preg_last_error(), ou preg_replace() filtrant sans contrôle !== null : un payload dépassant pcre.backtrack_limit fait renvoyer false/null en quelques millisecondes et désactive le filtre.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-STEALTH-UNICODE-TROJAN-SOURCE".to_string(),
                cve_id: "AETHER-BACKDOOR-001 / INVISIBLE-BIDI-AND-ZERO-WIDTH-TROJAN".to_string(),
                name: "Porte Dérobée Invisible: Unicode BiDi Trojan Source, Zero-Width & Homoglyphes".to_string(),
                category: "Polyglot / Invisible Backdoors".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Présence de caractères directionnels BiDi (U+202E/U+2066), caractères invisibles de largeur nulle / Tags Unicode (U+200B/U+E00xx), ou identifiants mixtes ASCII + Cyrillique/Grec masquant visuellement une logique malveillante ou une fonction sosie.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-PREMAIN-ELF-CONSTRUCTOR-BACKDOOR".to_string(),
                cve_id: "AETHER-BACKDOOR-002 / PREMAIN-LINK-SECTION-INIT-ARRAY".to_string(),
                name: "Porte Dérobée Invisible Rust: Exécution Pré-main (.init_array / ctor) & Hijack #[no_mangle]".to_string(),
                category: "Rust / Invisible Backdoors".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Injection d'un constructeur natif exécuté avant fn main() ou au dlopen() via #[link_section = \".init_array\"/.ctors] ou #[ctor], ou détournement de symbole libc/crypto/PAM via #[no_mangle] / #[export_name], totalement invisible dans le graphe d'appels.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-BUILD-RS-PROC-MACRO-BACKDOOR".to_string(),
                cve_id: "AETHER-BACKDOOR-003 / COMPILE-TIME-LATERAL-DROPPER".to_string(),
                name: "Porte Dérobée Invisible Rust: Dropper / Exfiltration Compile-Time (build.rs / proc_macro)".to_string(),
                category: "Rust / Invisible Backdoors".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Script build.rs ou proc_macro exécutant des connexions réseau, shells système, lecture de secrets CI/SSH/AWS ou générant des payloads dans OUT_DIR dès l'ouverture dans l'IDE (rust-analyzer) ou cargo check.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-STEALTH-ENGINE-BACKDOOR".to_string(),
                cve_id: "AETHER-BACKDOOR-004 / PHP-TICK-AUTOLOAD-VARFUNC-STEALTH".to_string(),
                name: "Porte Dérobée Invisible PHP: Ticks Zend, Variable-Function & Autoload/Stream Hijack".to_string(),
                category: "PHP / Invisible Backdoors".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Mécanisme d'exécution cachée sans eval()/system() explicite : register_tick_function / shutdown hook dynamique, invocation variable-fonction sur superglobale ou chaîne obfusquée (base64/gzinflate/str_rot13/chr), ou détournement stream_wrapper/spl_autoload.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-FFI-NATIVE-BRIDGE-RCE".to_string(),
                cve_id: "AETHER-RCE-001 / PHP-FFI-SHELLCODE-LIBC-BYPASS".to_string(),
                name: "RCE Furtive PHP via FFI: Pont Libc / Shellcode Mémoire (Bypass disable_functions)".to_string(),
                category: "PHP / Covert RCE Backdoors".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Utilisation de FFI::cdef/load/cast pour exposer des primitives natives système ou mémoire exécutable (system, execve, mmap, mprotect, VirtualAlloc, dlopen) sans appeler aucune fonction PHP surveillée par disable_functions ou les scanners CWE.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-CRYPTO-HEADER-EXOTIC-RCE".to_string(),
                cve_id: "AETHER-RCE-002 / CRYPTO-GATED-NO-EVAL-SINK-TRAPDOOR".to_string(),
                name: "RCE Furtive PHP: Trappe Crypto-Header & Puits Exotiques Sans eval()".to_string(),
                category: "PHP / Covert RCE Backdoors".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Exécution dynamique via puits ignorés des linters CWE (ob_start callback dynamique, mb_ereg_replace flag 'e', sqliteCreateFunction UDF, pcntl_exec, yaml_parse non restreint, include data://) souvent déclenchée par en-tête HTTP chiffré ou haché.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-OPCACHE-USERINI-PERSIST-RCE".to_string(),
                cve_id: "AETHER-RCE-003 / INI-PREPEND-OPCACHE-STEALTH-PERSIST".to_string(),
                name: "RCE Persistante PHP: Empoisonnement .user.ini / auto_prepend_file / Opcache".to_string(),
                category: "PHP / Covert RCE Backdoors".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Écriture ou injection dynamique ciblant .user.ini, php.ini, .htaccess (SetHandler PHP), auto_prepend_file, auto_append_file, opcache.preload ou opcache_compile_file() sur chemin dynamique : exécution furtive avant chaque requête HTTP sans upload .php.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-FILELESS-WX-MEMFD-RCE".to_string(),
                cve_id: "AETHER-RCE-004 / RUST-FILELESS-MMAP-MEMFD-EXEC".to_string(),
                name: "RCE Fileless Rust: Mémoire Exécutable W^X / memfd_create / Patch /proc/self/mem".to_string(),
                category: "Rust / Covert RCE Backdoors".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Exécution native 100% en mémoire sans Command::new ni écriture disque : pages PROT_EXEC / PAGE_EXECUTE_READWRITE, memfd_create + fexecve, écriture dans /proc/self/mem ou transmute d'un buffer brut vers extern \"C\" fn().".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-RKYV-UNCHECKED-RELPTR-RCE".to_string(),
                cve_id: "AETHER-RCE-005 / ZERO-COPY-ARCHIVED-VTABLE-HIJACK".to_string(),
                name: "RCE Zero-Copy Rust: Désérialisation rkyv Non Validée (RelPtr / Vtable Hijack)".to_string(),
                category: "Rust / Covert RCE Backdoors".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Appel à rkyv::archived_root, access_unchecked ou deserialize_unchecked sans validation bytecheck (check_archived_root / access) : permet de forger des RelPtr ou discriminants d'enum depuis le réseau pour détourner le contrôle de flux.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-GLOBAL-HOOK-TRAPDOOR-RCE".to_string(),
                cve_id: "AETHER-RCE-006 / GLOBAL-ALLOC-PANIC-SIGNAL-TRAPDOOR".to_string(),
                name: "Trappe Ambiante Rust: Payload Réseau/Exec dans #[global_allocator] ou panic::set_hook".to_string(),
                category: "Rust / Covert RCE Backdoors".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Hook global du runtime Rust (impl GlobalAlloc, std::panic::set_hook, sigaction) contenant des primitives réseau, shell, FFI ou mémoire exécutable : trappe déclenchable à distance sur n'importe quelle requête sans figurer dans les routeurs HTTP.".to_string(),
                default_enabled: true,
            },
            // --- 6 Nouvelles Pépites Sémantiques Rust ---
            CveRuleDef {
                rule_id: "AETHER-RUST-EPHEMERAL-LOCK-DROP".to_string(),
                cve_id: "AETHER-SYNC-007 / EPHEMERAL-MUTEX-GUARD-DROP".to_string(),
                name: "Drop Éphémère de MutexGuard/RwLockGuard via `let _ =` (Déverrouillage Instantané)".to_string(),
                category: "Rust / Async & Type Soundness".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Affectation `let _ = mutex.lock()` (ou `.write()` / `.read()`) : le RAII Guard est détruit à la fin de l'instruction avant la section critique, annulant l'exclusion mutuelle et exposant à des races TOCTOU silencieuses.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-PATH-JOIN-PREFIX-WIPE".to_string(),
                cve_id: "AETHER-PATH-008 / PATH-JOIN-ABSOLUTE-OVERWRITE".to_string(),
                name: "Écrasement de Racine par Path::join/push sur Entrée Non Confinée".to_string(),
                category: "Rust / Async & Type Soundness".to_string(),
                severity: "CRITICAL".to_string(),
                description: "En Rust, PathBuf::join(\"/etc/passwd\") ou push() sur un chemin non contrôlé contenant une racine/préfixe Windows remplace silencieusement tout le préfixe de base sans traversal `..`.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-ASSERT-UNWINDSAFE-STATE-TORN".to_string(),
                cve_id: "AETHER-PANIC-009 / ASSERT-UNWINDSAFE-MUT-CORRUPTION".to_string(),
                name: "AssertUnwindSafe sur Référence &mut dans catch_unwind (État Déchiré / Auth Fail-Open)".to_string(),
                category: "Rust / Async & Type Soundness".to_string(),
                severity: "HIGH".to_string(),
                description: "Forcer AssertUnwindSafe autour d'un état mutable capturé dans panic::catch_unwind casse l'invariant de sécurité après panique (soldes/ACL déchirés sans empoisonnement de verrou).".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-UTF8-LOSSY-SMUGGLING".to_string(),
                cve_id: "AETHER-NORM-010 / UTF8-LOSSY-REPLACEMENT-COLLISION".to_string(),
                name: "Contrebande d'Authentification/Signature via String::from_utf8_lossy (U+FFFD)".to_string(),
                category: "Rust / Async & Type Soundness".to_string(),
                severity: "HIGH".to_string(),
                description: "String::from_utf8_lossy normalise silencieusement des séquences d'octets invalides distinctes vers U+FFFD en contexte d'auth/HMAC/filtrage, créant des collisions entre octets vérifiés et consommés.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-UNANCHORED-REGEX-GATE".to_string(),
                cve_id: "AETHER-CTRL-011 / REGEX-SUBSTRING-IS-MATCH-BYPASS".to_string(),
                name: "Regex::is_match Sans Ancres Strictes (\\A.. \\z) sur Porte Allowlist/Origin/Role".to_string(),
                category: "Rust / Async & Type Soundness".to_string(),
                severity: "HIGH".to_string(),
                description: "regex::Regex::is_match effectue par défaut une recherche de sous-chaîne : une regex d'allowlist ou de domaine sans ancres strictes (ou avec ^/$ en multiline) est contournable par préfixe/suffixe/retour chariot.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-RUST-RELAXED-ATOMIC-SECURITY-GATE".to_string(),
                cve_id: "AETHER-MEM-012 / WEAK-RELAXED-ATOMIC-SECURITY-BARRIER".to_string(),
                name: "Barrière d'Authentification/Init Atomique sous Ordering::Relaxed (Réordonnancement CPU)".to_string(),
                category: "Rust / Async & Type Soundness".to_string(),
                severity: "HIGH".to_string(),
                description: "Utiliser Ordering::Relaxed sur un flag atomique de sécurité/initialisation (auth, admin, init, ready, sealed) ne garantit aucune relation happens-before sur architectures faiblement ordonnées (ARM64/RISC-V).".to_string(),
                default_enabled: true,
            },
            // --- 6 Nouvelles Pépites Sémantiques PHP / Zend Engine ---
            CveRuleDef {
                rule_id: "AETHER-PHP-LOOSE-INARRAY-BOOL-BYPASS".to_string(),
                cve_id: "AETHER-ZEND-007 / PHP8-INARRAY-BOOL-TRUE-JUGGLING".to_string(),
                name: "Contournement d'Allowlist PHP 8 par in_array()/array_search() Sans $strict = true".to_string(),
                category: "PHP / Zend Type & Parser Flaws".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Appeler in_array() ou array_search() sur des rôles/actions/algorithmes sans 3e paramètre `true` reste vulnérable au type juggling PHP 8 (ex: bool `true` égalise toute string non vide ou clé numérique).".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-PARSE-URL-DIFFERENTIAL-SSRF".to_string(),
                cve_id: "AETHER-ZEND-008 / PARSE-URL-LIBCURL-HOST-DIFFERENTIAL".to_string(),
                name: "SSRF par Désynchronisation Parseur parse_url() vs libcurl / Redirections".to_string(),
                category: "PHP / Zend Type & Parser Flaws".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Valider un hôte via parse_url() puis le transmettre à curl/file_get_contents sans validation IP post-résolution (CURLOPT_RESOLVE / FILTER_FLAG_NO_PRIV_RANGE) ou suivi de redirection non restreint expose au SSRF différentiel.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-ESCAPESHELLCMD-FLAG-RCE".to_string(),
                cve_id: "AETHER-ZEND-009 / ESCAPESHELLCMD-ARGUMENT-FLAG-INJECTION".to_string(),
                name: "Injection d'Options CLI / RCE via escapeshellcmd() à la Place de escapeshellarg()".to_string(),
                category: "PHP / Zend Type & Parser Flaws".to_string(),
                severity: "CRITICAL".to_string(),
                description: "escapeshellcmd() laisse passer les espaces et tirets : l'attaquant injecte des drapeaux CLI arbitraires (`--checkpoint-action=exec=...`, `-oProxyCommand=...`) jusqu'à l'exécution de commande.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-JSON-DEPTH-NULL-FAILOPEN".to_string(),
                cve_id: "AETHER-ZEND-010 / JSON-DECODE-DEPTH512-SILENT-NULL".to_string(),
                name: "Échec Silencieux json_decode() -> NULL (Depth/UTF-8) Sans JSON_THROW_ON_ERROR".to_string(),
                category: "PHP / Zend Type & Parser Flaws".to_string(),
                severity: "HIGH".to_string(),
                description: "Sur JSON profond (>512 niveaux) ou malformé, json_decode() renvoie silencieusement `null` sans exception ni erreur : sans JSON_THROW_ON_ERROR ou vérification stricte, la logique métier/JWT/ACL reçoit null.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-PDO-EMULATED-PREPARES-SMUGGLING".to_string(),
                cve_id: "AETHER-ZEND-011 / PDO-CLIENT-EMULATED-PREPARE-SMUGGLING".to_string(),
                name: "PDO MySQL avec ATTR_EMULATE_PREPARES Activé (Multi-Query & Parser Differential)".to_string(),
                category: "PHP / Zend Type & Parser Flaws".to_string(),
                severity: "HIGH".to_string(),
                description: "PDO active par défaut l'émulation côté client (ATTR_EMULATE_PREPARES = true), empêchant les vrais prepared statements binaires et ouvrant aux collisions de charset / contournements de quote / multi-requêtes.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "AETHER-PHP-CURLY-VAR-INTERPOLATION-RCE".to_string(),
                cve_id: "AETHER-ZEND-012 / PHP-COMPLEX-CURLY-SYNTAX-EXEC".to_string(),
                name: "Interpolation Complexe PHP {${func()}} / ${$_} dans Chaîne Double-Quote ou Heredoc".to_string(),
                category: "PHP / Zend Type & Parser Flaws".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Syntaxe PHP `{${...(...)}}` ou `${$_...}` au sein d'une chaîne double-quote ou heredoc : déclenche l'évaluation dynamique d'appel de fonction ou de superglobale comme primitive de RCE furtive ou d'exfiltration.".to_string(),
                default_enabled: true,
            },
        ]
    }

    /// Audit des règles sémantiques inédites et détecteurs de portes dérobées invisibles.
    pub fn audit_file(
        file_path: &str,
        content: &str,
        is_test_file: bool,
        is_interface_or_types: bool,
    ) -> Vec<LinterViolation> {
        let mut violations = Vec::new();
        let lower_path = file_path.to_lowercase().replace('\\', "/");
        let is_build_script = lower_path == "build.rs" || lower_path.ends_with("/build.rs");
        if (is_test_file && !is_build_script)
            || is_interface_or_types
            || lower_path.contains("epic_novel_rules.rs")
            || lower_path.contains("deep_rules.rs")
            || lower_path.contains("php_rules.rs")
        {
            return violations;
        }

        // 1. Polyglot Invisible Unicode / Trojan Source / Homoglyph Spoofing
        Self::audit_stealth_unicode_trojan(file_path, &lower_path, content, &mut violations);

        if lower_path.ends_with(".rs") {
            if !is_build_script {
                Self::audit_rust_async_tls_bleed(file_path, content, &mut violations);
                Self::audit_rust_serde_invariant_erasure(file_path, content, &mut violations);
                Self::audit_rust_async_frame_secret(file_path, content, &mut violations);
                Self::audit_rust_rkyv_unchecked(file_path, content, &mut violations);
                Self::audit_rust_ephemeral_lock_drop(file_path, content, &mut violations);
                Self::audit_rust_path_join_prefix_wipe(file_path, content, &mut violations);
                Self::audit_rust_assert_unwindsafe(file_path, content, &mut violations);
                Self::audit_rust_utf8_lossy_smuggling(file_path, content, &mut violations);
                Self::audit_rust_unanchored_regex_gate(file_path, content, &mut violations);
                Self::audit_rust_relaxed_atomic_gate(file_path, content, &mut violations);
            }
            Self::audit_rust_premain_backdoor(file_path, &lower_path, content, &mut violations);
            Self::audit_rust_build_proc_macro_backdoor(file_path, &lower_path, content, &mut violations);
            Self::audit_rust_fileless_wx_memfd_rce(file_path, &lower_path, content, &mut violations);
            Self::audit_rust_global_hook_trapdoor(file_path, content, &mut violations);
        }

        if crate::php_rules::PhpSecurityRules::is_php_file(&lower_path) {
            Self::audit_php_persistent_worker_bleed(file_path, content, &mut violations);
            Self::audit_php_generator_deferred_guard(file_path, content, &mut violations);
            Self::audit_php_pcre_backtrack_failopen(file_path, content, &mut violations);
            Self::audit_php_stealth_engine_backdoor(file_path, content, &mut violations);
            Self::audit_php_ffi_native_bridge(file_path, content, &mut violations);
            Self::audit_php_crypto_header_exotic_rce(file_path, content, &mut violations);
            Self::audit_php_opcache_userini_persist(file_path, content, &mut violations);
            Self::audit_php_loose_in_array_bool(file_path, content, &mut violations);
            Self::audit_php_parse_url_differential_ssrf(file_path, content, &mut violations);
            Self::audit_php_escapeshellcmd_flag_rce(file_path, content, &mut violations);
            Self::audit_php_json_depth_null_failopen(file_path, content, &mut violations);
            Self::audit_php_pdo_emulated_prepares(file_path, content, &mut violations);
            Self::audit_php_curly_var_interpolation(file_path, content, &mut violations);
        }

        violations
    }

    // -------------------------------------------------------------------------
    // Helpers de portée (Brace-tracked)
    // -------------------------------------------------------------------------

    fn collect_brace_scopes<'a>(
        lines: &[&'a str],
        header_pred: impl Fn(&str) -> bool,
    ) -> Vec<(usize, usize)> {
        let mut scopes = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let t = lines[i].trim();
            if header_pred(t) {
                if let Some(end) = Self::find_scope_end(lines, i) {
                    scopes.push((i, end));
                    i = end + 1;
                    continue;
                }
            }
            i += 1;
        }
        scopes
    }

    fn find_scope_end(lines: &[&str], start: usize) -> Option<usize> {
        let mut depth: isize = 0;
        let mut opened = false;
        for (idx, line) in lines.iter().enumerate().skip(start) {
            for ch in line.chars() {
                if ch == '{' {
                    depth += 1;
                    opened = true;
                } else if ch == '}' && opened {
                    depth -= 1;
                    if depth <= 0 {
                        return Some(idx);
                    }
                }
            }
            if !opened && line.trim_end().ends_with(';') {
                return None;
            }
        }
        None
    }

    fn has_token(line: &str, kw: &str) -> bool {
        let bytes = line.as_bytes();
        let kb = kw.as_bytes();
        if bytes.len() < kb.len() {
            return false;
        }
        let mut pos = 0;
        while let Some(rel) = line[pos..].find(kw) {
            let abs = pos + rel;
            let before_ok = abs == 0 || !is_ident_byte(bytes[abs - 1]);
            let after_idx = abs + kb.len();
            let after_ok = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
            if before_ok && after_ok {
                return true;
            }
            pos = abs + kb.len();
        }
        false
    }

    // -------------------------------------------------------------------------
    // 1. AETHER-RUST-ASYNC-TLS-BLEED
    // -------------------------------------------------------------------------
    fn audit_rust_async_tls_bleed(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        if !content.contains("async fn ") {
            return;
        }
        let has_tls_decl = content.contains("thread_local!");
        if !has_tls_decl && content.contains("task_local!") {
            return;
        }
        let lines: Vec<&str> = content.lines().collect();
        let scopes = Self::collect_brace_scopes(&lines, |t| {
            t.contains("async fn ") && !t.starts_with("//")
        });

        for (start, end) in scopes {
            let await_lines: Vec<usize> = (start..=end)
                .filter(|&i| lines[i].contains(".await"))
                .collect();
            if await_lines.is_empty() {
                continue;
            }
            let scope_slice = lines[start..=end].join("\n");
            let has_mutator = scope_slice.contains(".borrow_mut(")
                || scope_slice.contains(".set(")
                || scope_slice.contains(".replace(")
                || scope_slice.contains(".take(");

            for idx in start..=end {
                let t = lines[idx].trim();
                let is_tls_call = (has_tls_decl && t.contains(".with("))
                    || (t.contains(".with(|") && has_mutator);
                if !is_tls_call {
                    continue;
                }
                let Some(&next_await) = await_lines.iter().find(|&&a| a >= idx) else {
                    continue;
                };
                let cleared_before_await = lines[idx..=next_await].iter().any(|l| {
                    l.contains(".set(None)")
                        || l.contains(".replace(None)")
                        || l.contains(".take()")
                        || l.contains("reset_tls")
                });
                if !cleared_before_await {
                    out.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: idx + 1,
                        rule_id: "AETHER-RUST-ASYNC-TLS-BLEED".to_string(),
                        cve_id: "AETHER-EXEC-001 / ASYNC-WORKSTEAL-TLS-CONTAMINATION".to_string(),
                        severity: "CRITICAL".to_string(),
                        message: "☣️ [AETHER-EXEC-001] ASYNC_TLS_CONTAMINATION : Accès/mutation de thread_local! dans une async fn traversant un .await : le scheduler work-stealing peut migrer ou réutiliser ce thread OS pour une autre tâche et provoquer une fuite d'identité/tenant.".to_string(),
                        transmitted_data: Some("thread_local_across_await".to_string()),
                        transmitted_type: Some("LocalKey (Work-Stealing Tenant Bleed)".to_string()),
                        remediation: "Remplacer thread_local! par tokio::task_local! avec .scope(ctx, async move { ... }).await, ou isoler et purger le thread_local dans un bloc synchrone avant tout .await.".to_string(),
                    });
                    break;
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // 2. AETHER-RUST-SERDE-INVARIANT-ERASURE
    // -------------------------------------------------------------------------
    fn audit_rust_serde_invariant_erasure(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        if !content.contains("Deserialize") || !content.contains("struct ") {
            return;
        }
        let lines: Vec<&str> = content.lines().collect();
        for (idx, &raw) in lines.iter().enumerate() {
            let trimmed = raw.trim();
            if !trimmed.contains("struct ") || trimmed.starts_with("//") {
                continue;
            }
            let Some(name) = Self::extract_struct_name(trimmed) else {
                continue;
            };
            let attr_start = idx.saturating_sub(6);
            let attrs = lines[attr_start..idx].join(" ");
            if !Self::has_derive_deserialize(&attrs) || Self::has_serde_guard(&attrs) {
                continue;
            }
            if Self::has_manual_deserialize_impl(content, &name) {
                continue;
            }
            if !Self::struct_has_private_field(&lines, idx) {
                continue;
            }
            if Self::has_fallible_constructor(&lines, &name) {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-RUST-SERDE-INVARIANT-ERASURE".to_string(),
                    cve_id: "AETHER-TYPE-002 / SERDE-CONSTRUCTOR-INVARIANT-BYPASS".to_string(),
                    severity: "HIGH".to_string(),
                    message: format!("☣️ [AETHER-TYPE-002] SERDE_INVARIANT_ERASURE : La structure '{}' possède des champs privés et un constructeur faillible (Result/Option), mais dérive Deserialize sans #[serde(try_from = ...)] ni implémentation manuelle, permettant de contourner toute validation.", name),
                    transmitted_data: Some(format!("unvalidated_deserialized_{}", name)),
                    transmitted_type: Some("Struct (Smart-Constructor Bypass via Derive Macro)".to_string()),
                    remediation: "Ajouter #[serde(try_from = \"RawInput\")] (avec TryFrom validant les invariants) ou #[serde(deserialize_with = \"...\")] au lieu de dériver Deserialize directement.".to_string(),
                });
            }
        }
    }

    fn extract_struct_name(line: &str) -> Option<String> {
        let after = line.split("struct ").nth(1)?.trim_start();
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() { None } else { Some(name) }
    }

    fn has_derive_deserialize(attrs: &str) -> bool {
        attrs.contains("#[derive(")
            && (attrs.contains("Deserialize") || attrs.contains("BorshDeserialize"))
    }

    fn has_serde_guard(attrs: &str) -> bool {
        attrs.contains("try_from")
            || attrs.contains("from =")
            || attrs.contains("deserialize_with")
            || attrs.contains("try_into")
    }

    fn has_manual_deserialize_impl(content: &str, name: &str) -> bool {
        content.lines().any(|l| {
            let t = l.trim();
            t.starts_with("impl")
                && t.contains("Deserialize")
                && t.contains(&format!("for {}", name))
        })
    }

    fn struct_has_private_field(lines: &[&str], struct_idx: usize) -> bool {
        let head = lines[struct_idx].trim();
        if let (Some(lp), Some(rp)) = (head.find('('), head.rfind(')')) {
            if !head.contains('{') && rp > lp + 1 {
                return head[lp + 1..rp]
                    .split(',')
                    .map(str::trim)
                    .any(|f| !f.is_empty() && !f.starts_with("pub ") && !f.starts_with("pub("));
            }
        }
        let Some(end) = Self::find_scope_end(lines, struct_idx) else {
            return false;
        };
        if end <= struct_idx {
            let head = lines[struct_idx];
            if let (Some(open), Some(close)) = (head.find('{'), head.rfind('}')) {
                if close > open + 1 {
                    for f in head[open + 1..close].split(',') {
                        let f = f.trim();
                        if f.is_empty() || f.starts_with('#') || f.starts_with("//") {
                            continue;
                        }
                        if let Some((lhs, _)) = f.split_once(':') {
                            let lhs = lhs.trim();
                            let is_ident = !lhs.is_empty() && lhs.bytes().all(is_ident_byte);
                            if is_ident && !f.starts_with("pub ") && !f.starts_with("pub(") {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }
        for l in &lines[struct_idx + 1..end] {
            let f = l.trim();
            if f.is_empty() || f.starts_with('#') || f.starts_with("//") || f.starts_with("/*") || f.starts_with('*') {
                continue;
            }
            if let Some((lhs, _)) = f.split_once(':') {
                let lhs = lhs.trim();
                let is_ident = !lhs.is_empty() && lhs.bytes().all(is_ident_byte);
                if is_ident && !f.starts_with("pub ") && !f.starts_with("pub(") {
                    return true;
                }
            }
        }
        false
    }

    fn has_fallible_constructor(lines: &[&str], name: &str) -> bool {
        let impl_scopes = Self::collect_brace_scopes(lines, |t| {
            t.starts_with("impl")
                && !t.contains(" for ")
                && Self::has_token(t, name)
        });
        let ctors = ["fn new(", "fn try_new(", "fn parse(", "fn validate(", "fn build(", "fn from_"];
        impl_scopes.into_iter().any(|(s, e)| {
            lines[s..=e].iter().any(|l| {
                let t = l.trim();
                ctors.iter().any(|c| t.contains(c))
                    && (t.contains("-> Result") || t.contains("-> Option") || t.contains("Result<"))
            })
        })
    }

    // -------------------------------------------------------------------------
    // 3. AETHER-RUST-ASYNC-FRAME-SECRET-RESIDENCY
    // -------------------------------------------------------------------------
    fn audit_rust_async_frame_secret(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        if !content.contains("async fn ") || !content.contains(".await") {
            return;
        }
        let lines: Vec<&str> = content.lines().collect();
        let scopes = Self::collect_brace_scopes(&lines, |t| {
            t.contains("async fn ") && !t.starts_with("//")
        });
        let secret_markers = [
            "Zeroizing::new",
            "Secret::new",
            "SecretString",
            "SecretBox",
            "SigningKey",
            "PrivateKey",
            "MasterKey",
            "decrypt_key",
            "derive_key",
            "private_key",
            "secret_key",
            "signing_key",
            "seed_phrase",
            "mnemonic",
        ];

        for (start, end) in scopes {
            let await_lines: Vec<usize> = (start..=end)
                .filter(|&i| lines[i].contains(".await"))
                .collect();
            if await_lines.is_empty() {
                continue;
            }
            for idx in start..=end {
                let t = lines[idx].trim();
                if !t.starts_with("let ") || !secret_markers.iter().any(|m| t.contains(m)) {
                    continue;
                }
                if t.contains("Box::new(") || t.contains("Arc::new(") || t.contains("Box::pin(") {
                    continue;
                }
                let Some(&next_await) = await_lines.iter().find(|&&a| a > idx) else {
                    continue;
                };
                let var = Self::extract_let_ident(t);
                let zeroed_before = var.as_deref().map_or(false, |v| {
                    lines[idx + 1..=next_await].iter().any(|l| {
                        l.contains(&format!("drop({})", v))
                            || l.contains(&format!("{}.zeroize()", v))
                    })
                });
                if !zeroed_before {
                    out.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: idx + 1,
                        rule_id: "AETHER-RUST-ASYNC-FRAME-SECRET-RESIDENCY".to_string(),
                        cve_id: "AETHER-COMP-003 / COROUTINE-FRAME-SECRET-GHOSTING".to_string(),
                        severity: "HIGH".to_string(),
                        message: "☣️ [AETHER-COMP-003] COROUTINE_SECRET_GHOSTING : Secret cryptographique conservé vivant à travers un point .await dans une async fn : le compilateur copie les octets dans l'enum d'état du Future sur le tas, laissant des résidus même avec ZeroizeOnDrop.".to_string(),
                        transmitted_data: Some("spilled_async_secret_frame".to_string()),
                        transmitted_type: Some("CoroutineFrame (Unpinned Secret Residency Across .await)".to_string()),
                        remediation: "Isoler l'usage du secret dans une fonction/fermeture synchrone et le dropper avant .await, ou l'encapsuler dans Box<Zeroizing<T>> pour ne déplacer qu'un pointeur stable.".to_string(),
                    });
                }
            }
        }
    }

    fn extract_let_ident(line: &str) -> Option<String> {
        let rest = line.strip_prefix("let ")?.trim_start();
        let rest = rest.strip_prefix("mut ").unwrap_or(rest).trim_start();
        let ident: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if ident.is_empty() { None } else { Some(ident) }
    }

    // -------------------------------------------------------------------------
    // 4. AETHER-PHP-PERSISTENT-WORKER-BLEED
    // -------------------------------------------------------------------------
    fn audit_php_persistent_worker_bleed(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let masked_code = lexer::mask_literals(content, Lang::Php);
        let worker_markers = [
            "Octane",
            "Swoole",
            "OpenSwoole",
            "RoadRunner",
            "FrankenPHP",
            "frankenphp_handle_request",
            "Workerman",
            "React\\Http",
            "Amp\\Http",
        ];
        let has_worker_runtime = worker_markers.iter().any(|m| content.contains(m));
        let has_reset_hook = masked_code.contains("ResetInterface")
            || masked_code.contains("function reset(")
            || masked_code.contains("function flush(")
            || masked_code.contains("->reset(")
            || masked_code.contains("->flush(")
            || masked_code.contains("terminate(");
        if has_reset_hook {
            return;
        }

        let sensitive_names = [
            "user", "tenant", "auth", "token", "jwt", "claim", "session", "role",
            "permission", "request", "account", "identity",
        ];
        for (idx, line) in masked_code.lines().enumerate() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            let is_static_state_write = (t.contains("static $") && t.contains('='))
                || ((t.contains("self::$") || t.contains("static::$")) && t.contains('='))
                || (t.contains("$GLOBALS[") && t.contains('='));
            if !is_static_state_write {
                continue;
            }
            let lower_line = t.to_lowercase();
            let touches_identity = sensitive_names.iter().any(|s| lower_line.contains(s));
            if has_worker_runtime || touches_identity {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-PHP-PERSISTENT-WORKER-BLEED".to_string(),
                    cve_id: "AETHER-EXEC-004 / SHARED-NOTHING-RUNTIME-VIOLATION".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "☣️ [AETHER-EXEC-004] PERSISTENT_WORKER_STATE_BLEED : Mutation d'état statique/global (static $ / self::$ / $GLOBALS) sur contexte requête/identité sans ResetInterface ni purge : dans un worker persistant (Octane/FrankenPHP/Swoole/RoadRunner), cet état fuit vers les requêtes des clients suivants.".to_string(),
                    transmitted_data: Some("persistent_php_static_request_state".to_string()),
                    transmitted_type: Some("StaticZval (Cross-Request Memory Bleed)".to_string()),
                    remediation: "Supprimer l'état statique mutable ou implémenter Symfony\\Contracts\\Service\\ResetInterface / un listener Octane RequestTerminated pour réinitialiser chaque propriété après chaque requête.".to_string(),
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 5. AETHER-PHP-GENERATOR-DEFERRED-GUARD
    // -------------------------------------------------------------------------
    fn audit_php_generator_deferred_guard(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let masked_code = lexer::mask_literals(content, Lang::Php);
        if !masked_code.contains("yield") || !masked_code.contains("function ") {
            return;
        }
        let lines: Vec<&str> = masked_code.lines().collect();
        let scopes = Self::collect_brace_scopes(&lines, |t| {
            t.contains("function ") && !t.starts_with("abstract ")
        });
        let guard_tokens = [
            "throw ",
            "abort(",
            "http_response_code(",
            "isAdmin",
            "hasPermission",
            "hasRole",
            "authorize(",
            "checkAuth",
            "verifyToken",
            "deny(",
        ];

        for (start, end) in scopes {
            let yield_line = Self::find_direct_yield_in_php_fn(&lines, start, end);
            let guard_line = (start..=end)
                .find(|&i| guard_tokens.iter().any(|g| lines[i].contains(g)));
            if let (Some(y_idx), Some(g_idx)) = (yield_line, guard_line) {
                if g_idx < y_idx {
                    out.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: g_idx + 1,
                        rule_id: "AETHER-PHP-GENERATOR-DEFERRED-GUARD".to_string(),
                        cve_id: "AETHER-CTRL-005 / LAZY-YIELD-AUTH-BYPASS".to_string(),
                        severity: "CRITICAL".to_string(),
                        message: format!("☣️ [AETHER-CTRL-005] GENERATOR_DEFERRED_GUARD : Garde de sécurité ligne {} placé dans une fonction contenant 'yield' ligne {} : PHP transforme toute la fonction en Generator paresseux, aucune validation ne s'exécute à l'appel et l'objet retourné est toujours truthy.", g_idx + 1, y_idx + 1),
                        transmitted_data: Some("lazy_generator_bypassed_guard".to_string()),
                        transmitted_type: Some("Generator (Deferred Security Check Execution)".to_string()),
                        remediation: "Exécuter le garde d'authentification/validation de façon synchrone dans une fonction externe avant de retourner la closure/générateur interne.".to_string(),
                    });
                }
            }
        }
    }

    fn find_direct_yield_in_php_fn(lines: &[&str], start: usize, end: usize) -> Option<usize> {
        let mut depth: isize = 0;
        let mut nested_fn_base: Option<isize> = None;
        for idx in start..=end {
            let line = lines[idx];
            if idx > start && nested_fn_base.is_none() && line.contains("function ") {
                nested_fn_base = Some(depth);
            }
            if nested_fn_base.is_none() && Self::has_token(line, "yield") {
                return Some(idx);
            }
            for ch in line.chars() {
                if ch == '{' {
                    depth += 1;
                } else if ch == '}' {
                    depth -= 1;
                    if let Some(base) = nested_fn_base {
                        if depth <= base {
                            nested_fn_base = None;
                        }
                    }
                }
            }
        }
        None
    }

    // -------------------------------------------------------------------------
    // 6. AETHER-PHP-PCRE-BACKTRACK-FAILOPEN
    // -------------------------------------------------------------------------
    fn audit_php_pcre_backtrack_failopen(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        if !content.contains("preg_match")
            && !content.contains("preg_replace")
            && !content.contains("preg_filter")
        {
            return;
        }
        let has_err_guard = content.contains("preg_last_error")
            || content.contains("PREG_NO_ERROR")
            || content.contains("=== false")
            || content.contains("!== false");
        let has_null_guard = content.contains("=== null")
            || content.contains("!== null")
            || content.contains("is_string(");
        let filter_ctx = ["clean", "sanitiz", "filter", "escape", "strip", "waf", "safe", "xss", "sql"];

        for (idx, raw) in content.lines().enumerate() {
            let t = raw.trim();
            if t.is_empty() || t.starts_with("//") || t.starts_with('#') || t.starts_with('*') {
                continue;
            }
            let loose_preg_match = t.contains("!preg_match(")
                || (t.contains("preg_match(")
                    && (t.contains("== 0")
                        || t.contains("!= 1")
                        || t.contains("== false")
                        || t.contains("empty(preg_match")));
            if loose_preg_match && !has_err_guard {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-PHP-PCRE-BACKTRACK-FAILOPEN".to_string(),
                    cve_id: "AETHER-CTRL-006 / PCRE-LIMIT-SILENT-FAIL-OPEN".to_string(),
                    severity: "HIGH".to_string(),
                    message: "☣️ [AETHER-CTRL-006] PCRE_BACKTRACK_FAIL_OPEN : Contrôle négatif/faible sur preg_match() sans gestion de 'false' ni preg_last_error() : un payload dépassant pcre.backtrack_limit force preg_match() à retourner false (!false === true, false == 0) et désactive la règle en quelques ms.".to_string(),
                    transmitted_data: Some("pcre_backtrack_false_bypass".to_string()),
                    transmitted_type: Some("PcreResult (Silent Boolean Fail-Open)".to_string()),
                    remediation: "Vérifier strictement le retour === 1 (ou === 0) et rejeter explicitement === false / preg_last_error() !== PREG_NO_ERROR.".to_string(),
                });
                continue;
            }

            let is_replace_assign = (t.contains("= preg_replace(") || t.contains("= preg_filter("))
                && !t.contains("??")
                && !has_null_guard;
            if is_replace_assign && filter_ctx.iter().any(|k| t.to_lowercase().contains(k)) {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-PHP-PCRE-BACKTRACK-FAILOPEN".to_string(),
                    cve_id: "AETHER-CTRL-006 / PCRE-LIMIT-SILENT-FAIL-OPEN".to_string(),
                    severity: "HIGH".to_string(),
                    message: "☣️ [AETHER-CTRL-006] PCRE_REPLACE_SILENT_NULL : Résultat de preg_replace()/preg_filter() utilisé sans contrôle !== null ni preg_last_error() : en cas de dépassement pcre.backtrack_limit, la fonction retourne null silencieusement.".to_string(),
                    transmitted_data: Some("pcre_replace_null_collapse".to_string()),
                    transmitted_type: Some("PcreReplaceResult (Silent Null Collapse)".to_string()),
                    remediation: "Vérifier $res !== null && preg_last_error() === PREG_NO_ERROR et échouer de façon fermée (exception/rejet).".to_string(),
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 7. AETHER-STEALTH-UNICODE-TROJAN-SOURCE (Porte dérobée invisible)
    // -------------------------------------------------------------------------
    fn audit_stealth_unicode_trojan(
        file_path: &str,
        lower_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        if let Some((line_no, desc)) = Self::scan_invisible_trojan_chars(content) {
            out.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "AETHER-STEALTH-UNICODE-TROJAN-SOURCE".to_string(),
                cve_id: "AETHER-BACKDOOR-001 / INVISIBLE-BIDI-AND-ZERO-WIDTH-TROJAN".to_string(),
                severity: "CRITICAL".to_string(),
                message: format!("🕶️ [AETHER-BACKDOOR-001] INVISIBLE_TROJAN_UNICODE : {} — logique ou identifiant visuellement masqué à la relecture humaine.", desc),
                transmitted_data: Some("invisible_unicode_control_char".to_string()),
                transmitted_type: Some("TrojanSource (BiDi / Zero-Width / Tag Steganography)".to_string()),
                remediation: "Purger tous les caractères Unicode BiDi (U+202A..202E, U+2066..2069), invisibles de largeur nulle et Tags (U+E0000..E007F) via une règle CI ASCII-strict sur le code source.".to_string(),
            });
            return;
        }

        if let Some(lang) = Lang::from_path(lower_path) {
            let masked = lexer::mask_literals(content, lang);
            if let Some(line_no) = Self::scan_mixed_script_homoglyph(&masked) {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "AETHER-STEALTH-UNICODE-TROJAN-SOURCE".to_string(),
                    cve_id: "AETHER-BACKDOOR-001 / INVISIBLE-BIDI-AND-ZERO-WIDTH-TROJAN".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "🕶️ [AETHER-BACKDOOR-001] HOMOGLYPH_SHADOW_IDENTIFIER : Identifiant code mélangeant alphabet latin ASCII et caractères cyrilliques/grecs visuellement identiques (ex: 'а' U+0430 / 'о' U+043E) pour dissimuler une fonction ou variable porte dérobée.".to_string(),
                    transmitted_data: Some("mixed_script_homoglyph_identifier".to_string()),
                    transmitted_type: Some("ConfusableIdentifier (Stealth Symbol Shadowing)".to_string()),
                    remediation: "N'autoriser que les identifiants purement ASCII [A-Za-z0-9_] dans le code exécutable.".to_string(),
                });
            }
        }
    }

    fn scan_invisible_trojan_chars(content: &str) -> Option<(usize, String)> {
        for (line_idx, line) in content.lines().enumerate() {
            let chars: Vec<char> = line.chars().collect();
            for (ci, &ch) in chars.iter().enumerate() {
                if matches!(ch, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}') {
                    return Some((line_idx + 1, format!("Caractère de contrôle BiDi U+{:04X} (Trojan Source)", ch as u32)));
                }
                if matches!(ch, '\u{200B}' | '\u{200C}' | '\u{2060}' | '\u{00AD}' | '\u{034F}' | '\u{E0000}'..='\u{E007F}')
                    || (ch == '\u{FEFF}' && !(line_idx == 0 && ci == 0))
                {
                    return Some((line_idx + 1, format!("Caractère invisible / Tag Unicode U+{:04X}", ch as u32)));
                }
                if ch == '\u{200D}' && !Self::is_emoji_zwj(&chars, ci) {
                    return Some((line_idx + 1, "Zero-Width Joiner U+200D hors séquence emoji".to_string()));
                }
            }
        }
        None
    }

    fn is_emoji_zwj(chars: &[char], idx: usize) -> bool {
        let prev = chars[..idx]
            .iter()
            .rev()
            .find(|&&c| !matches!(c, '\u{FE0E}' | '\u{FE0F}'));
        let next = chars[idx + 1..]
            .iter()
            .find(|&&c| !matches!(c, '\u{FE0E}' | '\u{FE0F}'));
        matches!((prev, next), (Some(&p), Some(&n)) if p as u32 >= 0x2600 && n as u32 >= 0x2600)
    }

    fn scan_mixed_script_homoglyph(masked_code: &str) -> Option<usize> {
        for (idx, line) in masked_code.lines().enumerate() {
            for token in line.split(|c: char| !c.is_alphanumeric() && c != '_') {
                if token.is_empty() {
                    continue;
                }
                let has_ascii_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
                let has_confusable = token.chars().any(|c| {
                    matches!(c, '\u{0400}'..='\u{04FF}' | '\u{0370}'..='\u{03FF}')
                });
                if has_ascii_alpha && has_confusable {
                    return Some(idx + 1);
                }
            }
        }
        None
    }

    // -------------------------------------------------------------------------
    // 8. AETHER-RUST-PREMAIN-ELF-CONSTRUCTOR-BACKDOOR
    // -------------------------------------------------------------------------
    fn audit_rust_premain_backdoor(
        file_path: &str,
        lower_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        if lower_path.contains("/kernel") || lower_path.contains("/boot") || lower_path.contains("crt0") {
            return;
        }
        let no_comments = lexer::mask_comments_only(content, Lang::Rust);
        if !no_comments.contains("link_section")
            && !no_comments.contains("ctor")
            && !no_comments.contains("dtor")
            && !no_comments.contains("no_mangle")
            && !no_comments.contains("export_name")
        {
            return;
        }
        let lines: Vec<&str> = no_comments.lines().collect();
        let init_sections = [
            ".init_array", ".fini_array", ".preinit_array", ".ctors", ".dtors",
            ".CRT$X", "__mod_init_func", "__mod_term_func",
        ];
        let hijack_syms = [
            "fn malloc(", "fn free(", "fn calloc(", "fn realloc(", "fn memcmp(",
            "fn strcmp(", "fn dlopen(", "fn dlsym(", "fn execve(", "fn openat(",
            "fn pam_authenticate(", "fn CRYPTO_memcmp(", "fn SSL_read(", "fn SSL_write(",
        ];

        for (idx, line) in lines.iter().enumerate() {
            let win = lines[idx..(idx + 2).min(lines.len())].join(" ");
            let is_init_sec = (win.contains("#[link_section") && init_sections.iter().any(|s| win.contains(s)))
                || line.contains("#[ctor::ctor]")
                || line.contains("#[dtor::dtor]")
                || line.trim() == "#[ctor]";
            if is_init_sec {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-RUST-PREMAIN-ELF-CONSTRUCTOR-BACKDOOR".to_string(),
                    cve_id: "AETHER-BACKDOOR-002 / PREMAIN-LINK-SECTION-INIT-ARRAY".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "🕶️ [AETHER-BACKDOOR-002] PREMAIN_CONSTRUCTOR_BACKDOOR : Code enregistré dans une section constructeur native (.init_array/.ctors/#[ctor]) exécuté silencieusement avant fn main() ou au dlopen(), hors de tout graphe d'appel applicatif.".to_string(),
                    transmitted_data: Some("premain_elf_macho_pe_constructor".to_string()),
                    transmitted_type: Some("LinkerInitSection (Stealth Pre-Main Execution)".to_string()),
                    remediation: "Supprimer #[link_section]/.init_array/#[ctor] et initialiser explicitement les sous-systèmes depuis fn main().".to_string(),
                });
                continue;
            }

            if line.contains("#[no_mangle]") || line.contains("#[export_name") {
                let fn_win = lines[idx..(idx + 4).min(lines.len())].join(" ");
                let is_hijack = hijack_syms.iter().any(|sym| fn_win.contains(sym))
                    || (line.contains("#[export_name")
                        && ["\"malloc\"", "\"free\"", "\"memcmp\"", "\"strcmp\"", "\"dlopen\"", "\"execve\"", "\"pam_authenticate\""]
                            .iter()
                            .any(|s| line.contains(s)));
                if is_hijack {
                    out.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: idx + 1,
                        rule_id: "AETHER-RUST-PREMAIN-ELF-CONSTRUCTOR-BACKDOOR".to_string(),
                        cve_id: "AETHER-BACKDOOR-002 / PREMAIN-LINK-SECTION-INIT-ARRAY".to_string(),
                        severity: "CRITICAL".to_string(),
                        message: "🕶️ [AETHER-BACKDOOR-002] SYMBOL_INTERPOSITION_HIJACK : Attribut #[no_mangle] / #[export_name] redéfinissant un symbole critique libc/crypto/PAM : détourne tous les appels système ou cryptographiques à l'édition de liens sans jamais être appelé en Rust.".to_string(),
                        transmitted_data: Some("no_mangle_libc_interposition".to_string()),
                        transmitted_type: Some("ExportedLinkerSymbol (Silent GOT/Symbol Hijack)".to_string()),
                        remediation: "Interdire l'exportation de symboles réservés libc/OpenSSL/PAM via #[no_mangle] ou #[export_name].".to_string(),
                    });
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // 9. AETHER-RUST-BUILD-RS-PROC-MACRO-BACKDOOR
    // -------------------------------------------------------------------------
    fn audit_rust_build_proc_macro_backdoor(
        file_path: &str,
        lower_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let is_build = lower_path == "build.rs"
            || lower_path.ends_with("/build.rs")
            || lower_path.contains("/build/");
        let no_comments = lexer::mask_comments_only(content, Lang::Rust);
        let is_proc_macro = no_comments.contains("#[proc_macro");
        if !is_build && !is_proc_macro {
            return;
        }

        let bad_net = ["TcpStream::connect", "UdpSocket::connect", "UdpSocket::bind", "reqwest::", "ureq::", "hyper::Client"];
        let bad_shells = ["\"sh\"", "\"bash\"", "\"zsh\"", "\"cmd\"", "\"powershell\"", "\"pwsh\"", "\"curl\"", "\"wget\"", "\"python\"", "\"nc\""];
        let bad_secrets = ["\"GITHUB_TOKEN\"", "\"AWS_SECRET\"", "\"AWS_ACCESS_KEY\"", "\"CARGO_REGISTRY_TOKEN\"", "\"NPM_TOKEN\"", "\".ssh\"", "\".aws\"", "\".kube\"", "\"/etc/shadow\""];

        for (idx, line) in no_comments.lines().enumerate() {
            let net_hit = bad_net.iter().any(|p| line.contains(p));
            let shell_hit = line.contains("Command::new(") && bad_shells.iter().any(|s| line.contains(s));
            let secret_hit = bad_secrets.iter().any(|s| line.contains(s));
            let out_dir_drop = is_build
                && line.contains("OUT_DIR")
                && (no_comments.contains("TcpStream") || no_comments.contains(".init_array") || no_comments.contains("Command::new"));

            if net_hit || shell_hit || secret_hit || out_dir_drop {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-RUST-BUILD-RS-PROC-MACRO-BACKDOOR".to_string(),
                    cve_id: "AETHER-BACKDOOR-003 / COMPILE-TIME-LATERAL-DROPPER".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "🕶️ [AETHER-BACKDOOR-003] COMPILE_TIME_BACKDOOR : Code exécuté à la compilation (build.rs / #[proc_macro]) effectuant une connexion réseau, un shell OS, une lecture de secrets CI/SSH/AWS ou une injection OUT_DIR : compromission immédiate dès cargo check ou ouverture IDE.".to_string(),
                    transmitted_data: Some("compile_time_proc_macro_or_build_rs_exec".to_string()),
                    transmitted_type: Some("BuildScript / ProcMacro (IDE & CI Execution Backdoor)".to_string()),
                    remediation: "Supprimer tout accès réseau, shell générique et lecture de secrets hors cargo:rustc-* dans build.rs et les proc-macros.".to_string(),
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 10. AETHER-PHP-STEALTH-ENGINE-BACKDOOR
    // -------------------------------------------------------------------------
    fn audit_php_stealth_engine_backdoor(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let no_comments = lexer::mask_comments_only(content, Lang::Php);
        let taint_or_obf = [
            "$_GET", "$_POST", "$_COOKIE", "$_REQUEST", "$_SERVER",
            "base64_decode", "gzinflate", "gzuncompress", "str_rot13", "hex2bin", "chr(",
        ];
        let has_file_obf = taint_or_obf.iter().any(|p| no_comments.contains(p));
        let lines: Vec<&str> = no_comments.lines().collect();
        let mut tainted_callable_vars: Vec<String> = Vec::new();

        for (idx, &raw) in lines.iter().enumerate() {
            let t = raw.trim();
            if t.is_empty() {
                continue;
            }
            Self::track_php_callable_var(t, &taint_or_obf, &mut tainted_callable_vars);

            let win = lines[idx..(idx + 2).min(lines.len())].join(" ");
            let is_tick_or_hook = (t.contains("register_tick_function(")
                && (no_comments.contains("declare(ticks") || t.contains('$') || has_file_obf))
                || ((t.contains("register_shutdown_function(")
                    || t.contains("set_error_handler(")
                    || t.contains("set_exception_handler("))
                    && Self::has_tainted_arg(t, 0, &taint_or_obf, &tainted_callable_vars));

            let is_superglobal_call = Self::has_superglobal_or_varvar_invocation(t, &tainted_callable_vars);
            let is_higher_order_taint = Self::has_tainted_higher_order_callable(
                t,
                &taint_or_obf,
                &tainted_callable_vars,
            );

            let is_stealth_register = [
                "stream_wrapper_register(",
                "stream_filter_register(",
                "spl_autoload_register(",
                "ReflectionFunction(",
            ]
            .iter()
            .any(|f| t.contains(f))
                && (taint_or_obf.iter().any(|p| win.contains(p))
                    || tainted_callable_vars.iter().any(|v| Self::contains_php_var(&win, v))
                    || (has_file_obf && (no_comments.contains("HTTP_") || no_comments.contains("gzinflate") || no_comments.contains("base64_decode"))));

            if is_tick_or_hook || is_superglobal_call || is_higher_order_taint || is_stealth_register {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-PHP-STEALTH-ENGINE-BACKDOOR".to_string(),
                    cve_id: "AETHER-BACKDOOR-004 / PHP-TICK-AUTOLOAD-VARFUNC-STEALTH".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "🕶️ [AETHER-BACKDOOR-004] PHP_STEALTH_ENGINE_BACKDOOR : Mécanisme d'exécution cachée détecté (tick/shutdown handler, appel dynamique superglobal/$$var, callback obfusqué ou stream/autoload hijack) permettant une RCE sans eval() ni system() apparent.".to_string(),
                    transmitted_data: Some("stealth_php_runtime_hook".to_string()),
                    transmitted_type: Some("ZendRuntimeHook (Invisible Backdoor Trigger)".to_string()),
                    remediation: "Remplacer les invocations dynamiques et hooks Zend par une table de dispatch fermée (match / tableau associatif de callables littéraux) et supprimer tout décodeur obfusqué sur callable.".to_string(),
                });
            }
        }
    }

    fn track_php_callable_var(line: &str, taint_or_obf: &[&str], vars: &mut Vec<String>) {
        let Some((lhs, rhs)) = line.split_once('=') else {
            return;
        };
        if rhs.starts_with('=') {
            return;
        }
        let lhs = lhs.trim();
        if !lhs.starts_with('$') || lhs.contains('[') {
            return;
        }
        let name: String = lhs
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        let has_obf_rhs = taint_or_obf.iter().any(|p| rhs.contains(p))
            || Self::has_concat_danger_fn(rhs);
        if name.len() > 1 && has_obf_rhs && !vars.contains(&name) {
            vars.push(name);
        }
    }

    fn has_concat_danger_fn(s: &str) -> bool {
        ["'sys'.'tem'", "\"sys\".\"tem\"", "'ex'.'ec'", "'pas'.'sthru'", "'shell'.'_exec'", "'ass'.'ert'"]
            .iter()
            .any(|p| s.contains(p))
    }

    fn extract_call_arg(line: &str, fn_prefix: &str, arg_idx: usize) -> Option<String> {
        let pos = line.find(fn_prefix)?;
        let rest = &line[pos + fn_prefix.len()..];
        let mut depth = 1i32;
        let mut cur_arg = 0usize;
        let mut start = 0usize;
        for (i, ch) in rest.char_indices() {
            match ch {
                '(' | '[' => depth += 1,
                ')' | ']' => {
                    depth -= 1;
                    if depth == 0 {
                        if cur_arg == arg_idx {
                            return Some(rest[start..i].trim().to_string());
                        }
                        break;
                    }
                }
                ',' if depth == 1 => {
                    if cur_arg == arg_idx {
                        return Some(rest[start..i].trim().to_string());
                    }
                    cur_arg += 1;
                    start = i + 1;
                }
                _ => {}
            }
        }
        None
    }

    fn contains_php_var(s: &str, var: &str) -> bool {
        let bytes = s.as_bytes();
        let vb = var.as_bytes();
        let mut pos = 0;
        while let Some(rel) = s[pos..].find(var) {
            let after = pos + rel + vb.len();
            if after >= bytes.len() || !is_ident_byte(bytes[after]) {
                return true;
            }
            pos = after;
        }
        false
    }

    fn has_tainted_arg(
        line: &str,
        arg_idx: usize,
        taint_or_obf: &[&str],
        tainted_vars: &[String],
    ) -> bool {
        let fns = ["register_shutdown_function(", "set_error_handler(", "set_exception_handler("];
        fns.iter().any(|f| {
            Self::extract_call_arg(line, f, arg_idx).map_or(false, |arg| {
                taint_or_obf.iter().any(|p| arg.contains(p))
                    || tainted_vars.iter().any(|v| Self::contains_php_var(&arg, v))
            })
        })
    }

    fn has_tainted_higher_order_callable(
        line: &str,
        taint_or_obf: &[&str],
        tainted_vars: &[String],
    ) -> bool {
        let arg0_fns = ["call_user_func(", "call_user_func_array(", "array_map("];
        let arg1_fns = ["array_filter(", "usort(", "uasort(", "uksort(", "preg_replace_callback("];
        let check_arg = |fn_name: &str, idx: usize| -> bool {
            Self::extract_call_arg(line, fn_name, idx).map_or(false, |arg| {
                taint_or_obf.iter().any(|p| arg.contains(p))
                    || tainted_vars.iter().any(|v| Self::contains_php_var(&arg, v))
            })
        };
        arg0_fns.iter().any(|f| check_arg(f, 0)) || arg1_fns.iter().any(|f| check_arg(f, 1))
    }

    fn has_superglobal_or_varvar_invocation(line: &str, tainted_vars: &[String]) -> bool {
        let supers = ["$_GET[", "$_POST[", "$_COOKIE[", "$_REQUEST[", "$_SERVER["];
        let direct_super_call = supers.iter().any(|s| {
            line.find(s).map_or(false, |pos| {
                let tail = &line[pos + s.len()..];
                tail.find(']').map_or(false, |rb| tail[rb + 1..].trim_start().starts_with('('))
            })
        });
        let varvar_call = line.contains("$$") && line.contains('(');
        let concat_var_call = Self::has_concat_danger_fn(line) && line.contains('$');
        let tainted_var_call = tainted_vars.iter().any(|v| {
            let trimmed = line.trim_start();
            let is_self_assign = trimmed.starts_with(&format!("{} =", v)) || trimmed.starts_with(&format!("{}=", v));
            !is_self_assign && (line.contains(&format!("{}(", v)) || line.contains(&format!("({})(", v)))
        });
        direct_super_call || varvar_call || concat_var_call || tainted_var_call
    }

    // -------------------------------------------------------------------------
    // 11. AETHER-PHP-FFI-NATIVE-BRIDGE-RCE (AETHER-RCE-001)
    // -------------------------------------------------------------------------
    fn audit_php_ffi_native_bridge(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let no_comments = lexer::mask_comments_only(content, Lang::Php);
        if !no_comments.contains("FFI::") {
            return;
        }
        let dangerous_syms = [
            "system(", "execve(", "execl(", "popen(", "dlopen(", "dlsym(",
            "syscall(", "mmap(", "mprotect(", "virtualalloc", "virtualprotect",
            "winexec(", "createprocess", "rtlmovememory", "void(*)(", "void (*)()",
        ];
        let taint_or_dec = [
            "$_GET", "$_POST", "$_COOKIE", "$_REQUEST", "$_SERVER",
            "php://input", "base64_decode", "hex2bin", "gzinflate", "openssl_decrypt",
        ];
        let has_file_exec_alloc = ["mmap(", "mprotect(", "virtualalloc", "prot_exec"]
            .iter()
            .any(|m| no_comments.to_lowercase().contains(m));

        let lines: Vec<&str> = no_comments.lines().collect();
        for (idx, &raw) in lines.iter().enumerate() {
            let t = raw.trim();
            if t.is_empty() {
                continue;
            }
            let win = lines[idx..(idx + 4).min(lines.len())].join(" ");
            let lower_win = win.to_lowercase();

            let cdef_hit = (t.contains("FFI::cdef(") || t.contains("FFI::load(") || t.contains("FFI::scope("))
                && (dangerous_syms.iter().any(|s| lower_win.contains(s))
                    || Self::extract_call_arg(t, "FFI::cdef(", 0).map_or(false, |a| {
                        taint_or_dec.iter().any(|p| a.contains(p)) || a.starts_with('$')
                    }));
            let cast_hit = t.contains("FFI::cast(") && (t.contains("(*)") || t.contains("void("));
            let memcpy_hit = t.contains("FFI::memcpy(")
                && (taint_or_dec.iter().any(|p| win.contains(p)) || has_file_exec_alloc);

            if cdef_hit || cast_hit || memcpy_hit {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-PHP-FFI-NATIVE-BRIDGE-RCE".to_string(),
                    cve_id: "AETHER-RCE-001 / PHP-FFI-SHELLCODE-LIBC-BYPASS".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "☢️ [AETHER-RCE-001] PHP_FFI_NATIVE_RCE : Usage de FFI::cdef/cast/memcpy exposant des primitives système/mémoire exécutable (system/mmap/mprotect/VirtualAlloc) : contourne disable_functions sans appel eval() ou exec().".to_string(),
                    transmitted_data: Some("ffi_native_exec_bridge".to_string()),
                    transmitted_type: Some("ZendFFI (Native Shellcode / Libc Bypass)".to_string()),
                    remediation: "Désactiver ffi.enable en production et interdire tout FFI::cdef/cast vers libc/kernel32 ou allocation RWX.".to_string(),
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 12. AETHER-PHP-CRYPTO-HEADER-EXOTIC-RCE (AETHER-RCE-002)
    // -------------------------------------------------------------------------
    fn is_dynamic_or_tainted_expr(arg: &str, markers: &[&str], tainted_vars: &[String]) -> bool {
        let a = arg.trim();
        if a.is_empty() {
            return false;
        }
        let direct_var = a.starts_with('$') && a != "$this" && !a.starts_with("function");
        direct_var
            || markers.iter().any(|m| a.contains(m))
            || tainted_vars.iter().any(|v| Self::contains_php_var(a, v))
            || Self::has_concat_danger_fn(a)
    }

    fn audit_php_crypto_header_exotic_rce(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let no_comments = lexer::mask_comments_only(content, Lang::Php);
        let markers = [
            "$_GET", "$_POST", "$_COOKIE", "$_REQUEST", "$_SERVER",
            "php://input", "getallheaders(", "openssl_decrypt",
            "base64_decode", "gzinflate", "gzuncompress", "str_rot13", "hex2bin", "chr(",
        ];
        let lines: Vec<&str> = no_comments.lines().collect();
        let mut tainted_vars: Vec<String> = Vec::new();
        let decode_php_disabled = no_comments.contains("yaml.decode_php', '0'")
            || no_comments.contains("yaml.decode_php\", \"0\"");

        for (idx, &raw) in lines.iter().enumerate() {
            let t = raw.trim();
            if t.is_empty() {
                continue;
            }
            Self::track_php_callable_var(t, &markers, &mut tainted_vars);
            let win = lines[idx..(idx + 2).min(lines.len())].join(" ");

            let ob_hit = Self::extract_call_arg(t, "ob_start(", 0)
                .map_or(false, |a| Self::is_dynamic_or_tainted_expr(&a, &markers, &tainted_vars));

            let mb_eval_hit = ["mb_ereg_replace(", "mb_eregi_replace("].iter().any(|f| {
                Self::extract_call_arg(t, f, 3).map_or(false, |opt| {
                    (opt.contains('\'') || opt.contains('"')) && opt.contains('e')
                        || opt.starts_with('$')
                })
            });

            let sqlite_udf_hit = ["->sqliteCreateFunction(", "->createFunction("].iter().any(|f| {
                Self::extract_call_arg(t, f, 1)
                    .map_or(false, |cb| Self::is_dynamic_or_tainted_expr(&cb, &markers, &tainted_vars))
            });

            let pcntl_hit = ["pcntl_exec(", "expect_popen("].iter().any(|f| {
                Self::extract_call_arg(t, f, 0)
                    .map_or(false, |cmd| Self::is_dynamic_or_tainted_expr(&cmd, &markers, &tainted_vars))
            });

            let yaml_hit = !decode_php_disabled
                && ["yaml_parse(", "yaml_parse_file("].iter().any(|f| {
                    !win.contains("callbacks")
                        && Self::extract_call_arg(t, f, 0).map_or(false, |src| {
                            markers.iter().any(|m| src.contains(m))
                                || tainted_vars.iter().any(|v| Self::contains_php_var(&src, v))
                        })
                });

            let data_wrapper_inc = (Self::has_token(t, "include")
                || Self::has_token(t, "include_once")
                || Self::has_token(t, "require")
                || Self::has_token(t, "require_once"))
                && t.contains("data://")
                && (t.contains("base64") || t.contains('$'));

            if ob_hit || mb_eval_hit || sqlite_udf_hit || pcntl_hit || yaml_hit || data_wrapper_inc {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-PHP-CRYPTO-HEADER-EXOTIC-RCE".to_string(),
                    cve_id: "AETHER-RCE-002 / CRYPTO-GATED-NO-EVAL-SINK-TRAPDOOR".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "☢️ [AETHER-RCE-002] PHP_EXOTIC_NO_EVAL_RCE : Exécution dynamique via puits hors-CWE (ob_start callback dynamique, mb_ereg_replace /e, sqliteCreateFunction UDF, pcntl_exec, yaml_parse ou data:// include) : permet une RCE furtive sans eval()/system().".to_string(),
                    transmitted_data: Some("exotic_no_eval_php_rce_sink".to_string()),
                    transmitted_type: Some("ExoticPhpSink (Header/Crypto-Gated RCE)".to_string()),
                    remediation: "Remplacer ob_start/mb_ereg_replace 'e'/UDF/yaml_parse non filtrés par des callbacks statiques littéraux et désactiver yaml.decode_php = 0.".to_string(),
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 13. AETHER-PHP-OPCACHE-USERINI-PERSIST-RCE (AETHER-RCE-003)
    // -------------------------------------------------------------------------
    fn audit_php_opcache_userini_persist(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let no_comments = lexer::mask_comments_only(content, Lang::Php);
        let quick_hits = [
            "user.ini", "php.ini", ".htaccess", "auto_prepend_file",
            "auto_append_file", "opcache.preload", "zend_extension",
            "opcache_compile_file", "ini_set(",
        ];
        if !quick_hits.iter().any(|h| no_comments.contains(h)) {
            return;
        }
        let write_fns = ["file_put_contents(", "fwrite(", "fputs(", "move_uploaded_file(", "copy(", "rename("];
        let ini_directives = [".user.ini", "php.ini", "auto_prepend_file", "auto_append_file", "opcache.preload", "zend_extension"];
        let taint_src = ["$_GET", "$_POST", "$_COOKIE", "$_REQUEST", "$_FILES", "base64_decode", "gzinflate", "openssl_decrypt", "/tmp", "upload"];

        let lines: Vec<&str> = no_comments.lines().collect();
        for (idx, &raw) in lines.iter().enumerate() {
            let t = raw.trim();
            if t.is_empty() {
                continue;
            }
            let start = idx.saturating_sub(1);
            let end = (idx + 3).min(lines.len());
            let win = lines[start..end].join(" ");

            let ini_write_hit = write_fns.iter().any(|w| t.contains(w))
                && (ini_directives.iter().any(|d| win.contains(d))
                    || (win.contains(".htaccess")
                        && (win.contains("application/x-httpd-php") || win.contains("SetHandler") || win.contains("AddType"))));

            let ini_set_hit = t.contains("ini_set(")
                && (t.contains("auto_prepend_file") || t.contains("auto_append_file") || t.contains("opcache.preload"))
                && Self::extract_call_arg(t, "ini_set(", 1).map_or(false, |v| {
                    v.contains('$') || taint_src.iter().any(|s| v.contains(s))
                });

            let inc_path_hit = t.contains("ini_set(")
                && t.contains("include_path")
                && !t.contains("__DIR__")
                && Self::extract_call_arg(t, "ini_set(", 1)
                    .map_or(false, |v| taint_src.iter().any(|s| v.contains(s)) || v.starts_with('$'));

            let opcache_hit = Self::extract_call_arg(t, "opcache_compile_file(", 0).map_or(false, |p| {
                p.contains('$') || taint_src.iter().any(|s| p.contains(s))
            });

            if ini_write_hit || ini_set_hit || inc_path_hit || opcache_hit {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-PHP-OPCACHE-USERINI-PERSIST-RCE".to_string(),
                    cve_id: "AETHER-RCE-003 / INI-PREPEND-OPCACHE-STEALTH-PERSIST".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "☢️ [AETHER-RCE-003] PHP_INI_OPCACHE_PERSIST : Écriture ou injection dynamique dans .user.ini/auto_prepend_file/.htaccess/opcache_compile_file : permet une persistance RCE invisible déclenchée avant chaque requête HTTP sans aucun upload .php.".to_string(),
                    transmitted_data: Some("php_ini_opcache_persistence".to_string()),
                    transmitted_type: Some("IniPrependDirective (Stealth Runtime Persistence)".to_string()),
                    remediation: "Interdire toute écriture applicative de fichiers .user.ini/.htaccess et figer auto_prepend_file / opcache.preload dans php.ini en lecture seule.".to_string(),
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 14. AETHER-RUST-FILELESS-WX-MEMFD-RCE (AETHER-RCE-004)
    // -------------------------------------------------------------------------
    fn audit_rust_fileless_wx_memfd_rce(
        file_path: &str,
        lower_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        if lower_path.contains("/kernel")
            || lower_path.contains("/boot")
            || lower_path.contains("/jit")
            || lower_path.contains("/cranelift")
        {
            return;
        }
        let no_comments = lexer::mask_comments_only(content, Lang::Rust);
        let has_fs_write = (no_comments.contains("OpenOptions")
            && (no_comments.contains(".write(true)") || no_comments.contains(".write_all")))
            || no_comments.contains("fs::write")
            || no_comments.contains("pwrite(");

        let lines: Vec<&str> = no_comments.lines().collect();
        for (idx, &raw) in lines.iter().enumerate() {
            let t = raw.trim();
            if t.is_empty() {
                continue;
            }
            let win = lines[idx.saturating_sub(2)..(idx + 2).min(lines.len())].join(" ");
            let wx_hit = t.contains("PROT_EXEC")
                || t.contains("PAGE_EXECUTE_READWRITE")
                || t.contains("PAGE_EXECUTE_WRITECOPY")
                || t.contains("memfd_create(")
                || t.contains("fexecve(")
                || t.contains("execveat(")
                || t.contains("process_vm_writev(");

            let proc_mem_hit = (t.contains("\"/proc/self/mem\"") || t.contains("\"/proc/thread-self/mem\""))
                && has_fs_write;

            let fn_ptr_transmute = t.contains("transmute")
                && (t.contains("extern \"C\" fn")
                    || t.contains("extern \"system\" fn")
                    || t.contains(": fn(")
                    || t.contains(", fn(")
                    || t.contains("<_, fn("))
                && (win.contains("as_ptr()")
                    || win.contains("*const")
                    || win.contains("*mut")
                    || win.contains("mmap")
                    || win.contains("PROT_EXEC")
                    || win.contains("buf")
                    || win.contains("payload")
                    || win.contains("shellcode"));

            if wx_hit || proc_mem_hit || fn_ptr_transmute {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-RUST-FILELESS-WX-MEMFD-RCE".to_string(),
                    cve_id: "AETHER-RCE-004 / RUST-FILELESS-MMAP-MEMFD-EXEC".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "☢️ [AETHER-RCE-004] RUST_FILELESS_EXEC_RCE : Primitive d'exécution 100% en mémoire détectée (PROT_EXEC / PAGE_EXECUTE_READWRITE / memfd_create+fexecve / /proc/self/mem write / transmute vers fn()) sans Command::new ni binaire sur disque.".to_string(),
                    transmitted_data: Some("fileless_wx_memory_exec".to_string()),
                    transmitted_type: Some("FilelessMemoryExec (In-Memory Shellcode / Self-Patch)".to_string()),
                    remediation: "Supprimer toute allocation W^X (PROT_EXEC), memfd_create, écriture /proc/self/mem ou transmutation de buffer en pointeur de fonction.".to_string(),
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 15. AETHER-RUST-RKYV-UNCHECKED-RELPTR-RCE (AETHER-RCE-005)
    // -------------------------------------------------------------------------
    fn audit_rust_rkyv_unchecked(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let no_comments = lexer::mask_comments_only(content, Lang::Rust);
        if !no_comments.contains("rkyv::")
            && !no_comments.contains("archived_root")
            && !no_comments.contains("access_unchecked")
            && !no_comments.contains("deserialize_unchecked")
        {
            return;
        }
        for (idx, raw) in no_comments.lines().enumerate() {
            let t = raw.trim();
            if t.is_empty() {
                continue;
            }
            let unchecked_root = (t.contains("archived_root::<")
                || t.contains("archived_root(")
                || t.contains("archived_root_mut::<")
                || t.contains("archived_root_mut("))
                && !t.contains("check_archived_root");
            let unchecked_access = t.contains("access_unchecked::<")
                || t.contains("access_unchecked(")
                || t.contains("deserialize_unchecked::<")
                || t.contains("deserialize_unchecked(");

            if unchecked_root || unchecked_access {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: idx + 1,
                    rule_id: "AETHER-RUST-RKYV-UNCHECKED-RELPTR-RCE".to_string(),
                    cve_id: "AETHER-RCE-005 / ZERO-COPY-ARCHIVED-VTABLE-HIJACK".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "☢️ [AETHER-RCE-005] RKYV_UNCHECKED_ZERO_COPY : Désérialisation zero-copy rkyv non validée (archived_root / access_unchecked / deserialize_unchecked) : un attaquant forge RelPtr ou discriminants d'enum depuis le réseau pour détourner le contrôle de flux (RCE/UB).".to_string(),
                    transmitted_data: Some("unvalidated_rkyv_relptr".to_string()),
                    transmitted_type: Some("ZeroCopyArchive (Untrusted RelPtr / Enum Tag Corruption)".to_string()),
                    remediation: "Remplacer par rkyv::check_archived_root::<T>(bytes) ou rkyv::access::<Archived<T>, Error>(bytes) avec validation bytecheck.".to_string(),
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 16. AETHER-RUST-GLOBAL-HOOK-TRAPDOOR-RCE (AETHER-RCE-006)
    // -------------------------------------------------------------------------
    fn find_call_statement_end(lines: &[&str], start: usize) -> usize {
        let mut paren = 0isize;
        let mut brace = 0isize;
        let mut saw_open = false;
        for (idx, line) in lines.iter().enumerate().skip(start) {
            for ch in line.chars() {
                match ch {
                    '(' => {
                        paren += 1;
                        saw_open = true;
                    }
                    ')' => paren -= 1,
                    '{' => {
                        brace += 1;
                        saw_open = true;
                    }
                    '}' => brace -= 1,
                    ';' if saw_open && paren <= 0 && brace <= 0 => return idx,
                    _ => {}
                }
            }
            if saw_open && paren <= 0 && brace <= 0 && line.trim_end().ends_with(';') {
                return idx;
            }
        }
        (start + 1).min(lines.len().saturating_sub(1))
    }

    fn audit_rust_global_hook_trapdoor(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let no_comments = lexer::mask_comments_only(content, Lang::Rust);
        if !no_comments.contains("global_allocator")
            && !no_comments.contains("GlobalAlloc")
            && !no_comments.contains("panic::set_hook")
            && !no_comments.contains("sigaction")
        {
            return;
        }
        let covert_markers = [
            "TcpStream::", "UdpSocket::", "reqwest::", "ureq::", "hyper::",
            "Command::new(", "libc::system", "libc::exec", "fexecve(",
            "memfd_create(", "PROT_EXEC", "mprotect(", "dlopen(",
            "\"/proc/self/mem\"", "transmute", "GITHUB_TOKEN", "AWS_SECRET", "\".ssh\"",
        ];
        let lines: Vec<&str> = no_comments.lines().collect();

        // Scope A: impl GlobalAlloc { ... }
        let alloc_scopes = Self::collect_brace_scopes(&lines, |t| {
            t.contains("impl") && Self::has_token(t, "GlobalAlloc") && !t.contains("trait ")
        });
        for (s, e) in alloc_scopes {
            if let Some(hit) = (s..=e).find(|&i| covert_markers.iter().any(|m| lines[i].contains(m))) {
                out.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: hit + 1,
                    rule_id: "AETHER-RUST-GLOBAL-HOOK-TRAPDOOR-RCE".to_string(),
                    cve_id: "AETHER-RCE-006 / GLOBAL-ALLOC-PANIC-SIGNAL-TRAPDOOR".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "☢️ [AETHER-RCE-006] GLOBAL_ALLOC_TRAPDOOR : Primitive réseau, shell, FFI ou W^X détectée à l'intérieur d'un impl GlobalAlloc : trappe ambiante inspectant ou détournant les buffers alloués hors de tout routeur HTTP.".to_string(),
                    transmitted_data: Some("global_allocator_covert_hook".to_string()),
                    transmitted_type: Some("GlobalAllocHook (Ambient Heap Trapdoor)".to_string()),
                    remediation: "Restreindre GlobalAlloc aux opérations pures d'allocation mémoire sans I/O réseau, processus ni FFI exécutable.".to_string(),
                });
            }
        }

        // Scope B: panic::set_hook(...) / sigaction(...)
        for (idx, &raw) in lines.iter().enumerate() {
            if raw.contains("panic::set_hook(") || raw.contains("sigaction(") {
                let end = Self::find_call_statement_end(&lines, idx);
                if let Some(hit) = (idx..=end).find(|&i| covert_markers.iter().any(|m| lines[i].contains(m))) {
                    out.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: hit + 1,
                        rule_id: "AETHER-RUST-GLOBAL-HOOK-TRAPDOOR-RCE".to_string(),
                        cve_id: "AETHER-RCE-006 / GLOBAL-ALLOC-PANIC-SIGNAL-TRAPDOOR".to_string(),
                        severity: "CRITICAL".to_string(),
                        message: "☢️ [AETHER-RCE-006] PANIC_SIGNAL_TRAPDOOR : Primitive réseau, shell ou mémoire exécutable déclenchée dans panic::set_hook / sigaction : backdoor activable à distance en provoquant une panique ou erreur de parsing.".to_string(),
                        transmitted_data: Some("panic_or_signal_covert_hook".to_string()),
                        transmitted_type: Some("PanicSignalHook (Remote Trigger Trapdoor)".to_string()),
                        remediation: "Limiter les panic/signal hooks au logging diagnostic local et supprimer tout appel réseau, shell ou W^X.".to_string(),
                    });
                }
            }
        }
    }

    fn push_rule(
        out: &mut Vec<LinterViolation>,
        file_path: &str,
        line_number: usize,
        rule_id: &str,
        cve_id: &str,
        severity: &str,
        message: String,
        transmitted_data: &str,
        transmitted_type: &str,
        remediation: &str,
    ) {
        out.push(LinterViolation {
            file_path: file_path.to_string(),
            line_number,
            rule_id: rule_id.to_string(),
            cve_id: cve_id.to_string(),
            severity: severity.to_string(),
            message,
            transmitted_data: Some(transmitted_data.to_string()),
            transmitted_type: Some(transmitted_type.to_string()),
            remediation: remediation.to_string(),
        });
    }

    fn extract_arg_at(text: &str, open_paren: usize, arg_idx: usize) -> Option<String> {
        let bytes = text.as_bytes();
        let mut depth_paren = 1i32;
        let mut depth_bracket = 0i32;
        let mut depth_brace = 0i32;
        let mut in_sq = false;
        let mut in_dq = false;
        let mut escaped = false;
        let mut cur_arg = 0usize;
        let mut start = open_paren;
        for i in open_paren..bytes.len() {
            let b = bytes[i];
            if escaped {
                escaped = false;
                continue;
            }
            if (in_sq || in_dq) && b == b'\\' {
                escaped = true;
                continue;
            }
            if !in_dq && b == b'\'' {
                in_sq = !in_sq;
                continue;
            }
            if !in_sq && b == b'"' {
                in_dq = !in_dq;
                continue;
            }
            if in_sq || in_dq {
                continue;
            }
            match b {
                b'(' => depth_paren += 1,
                b')' => {
                    depth_paren -= 1;
                    if depth_paren == 0 {
                        if cur_arg == arg_idx {
                            return Some(text[start..i].trim().to_string());
                        }
                        return None;
                    }
                }
                b'[' => depth_bracket += 1,
                b']' => depth_bracket = (depth_bracket - 1).max(0),
                b'{' => depth_brace += 1,
                b'}' => depth_brace = (depth_brace - 1).max(0),
                b',' if depth_paren == 1 && depth_bracket == 0 && depth_brace == 0 => {
                    if cur_arg == arg_idx {
                        return Some(text[start..i].trim().to_string());
                    }
                    cur_arg += 1;
                    start = i + 1;
                }
                _ => {}
            }
        }
        None
    }

    fn extract_balanced_call_arg(text: &str, call_name: &str, arg_idx: usize) -> Option<String> {
        let lower = text.to_lowercase();
        let needle = format!("{}(", call_name.to_lowercase());
        let pos = lower.find(&needle)?;
        Self::extract_arg_at(text, pos + needle.len(), arg_idx)
    }

    // -----------------------------------------------------------------------
    // 6 NOUVELLES PÉPITES SÉMANTIQUES RUST
    // -----------------------------------------------------------------------

    fn audit_rust_ephemeral_lock_drop(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let lock_calls = [
            ".lock()",
            ".write()",
            ".read()",
            ".blocking_lock()",
            ".blocking_write()",
            ".blocking_read()",
            ".try_lock()",
            ".try_write()",
            ".try_read()",
        ];
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            let Some((lhs, rhs)) = trimmed.split_once('=') else {
                continue;
            };
            let lhs_clean = lhs.trim();
            let is_discard = lhs_clean == "let _" || lhs_clean.starts_with("let _:");
            if !is_discard || !lock_calls.iter().any(|c| rhs.contains(c)) {
                continue;
            }
            if rhs.contains(".is_ok()") || rhs.contains(".is_err()") || rhs.contains(".is_poisoned()") {
                continue;
            }
            Self::push_rule(
                out,
                file_path,
                idx + 1,
                "AETHER-RUST-EPHEMERAL-LOCK-DROP",
                "AETHER-SYNC-007 / EPHEMERAL-MUTEX-GUARD-DROP",
                "CRITICAL",
                "🔒 [AETHER-SYNC-007] EPHEMERAL_LOCK_GUARD_DROP : `let _ = ...lock()` détruit le Guard RAII dès la fin de l'instruction avant la section critique (exclusion mutuelle annulée / TOCTOU).".to_string(),
                "let _ = lock_guard_discarded",
                "EphemeralLockDrop",
                "Lier le guard à une variable nommée (`let _guard = mutex.lock()...;`) jusqu'à la fin de la section critique.",
            );
        }
    }

    fn audit_rust_path_join_prefix_wipe(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        if !content.contains(".join(") && !content.contains(".push(") {
            return;
        }
        let lines: Vec<&str> = content.lines().collect();
        let fn_scopes = Self::collect_brace_scopes(&lines, |t| Self::has_token(t, "fn"));
        let confine_markers = [
            ".is_absolute()",
            ".has_root()",
            "Component::Normal",
            "Component::ParentDir",
            "Component::RootDir",
            ".components()",
            ".canonicalize(",
            "starts_with('/')",
            "starts_with('\\\\'",
            "strip_prefix('/'",
            "trim_start_matches('/'",
            "PathGuard",
            "TargetJail",
            "sanitize_path",
            "validate_path",
        ];
        let fs_markers = [
            "fs::", "File::", "OpenOptions::", "Path::new", "PathBuf::from",
            ".to_path_buf()", "read_to_string", "remove_file", "create_dir",
        ];
        let untrusted_cues = [
            "user", "req", "input", "param", "query", "upload", "filename",
            "file_name", "entry", "rel", "subpath", "client", "payload", "body",
            "header", "tar", "zip", "archive", "untrusted", "requested",
        ];
        let path_recv_cues = ["path", "dir", "root", "base", "dest", "buf", "upload", "jail", "work", "sandbox"];
        let slice_recv_cues = ["parts", "segments", "lines", "words", "tokens", "items", "args", "cols", "fields", "collect"];

        for (s, e) in fn_scopes {
            let block: String = lines[s..=e].join("\n");
            let lower_block = block.to_lowercase();
            if confine_markers.iter().any(|m| block.contains(m))
                || !fs_markers.iter().any(|m| block.contains(m))
            {
                continue;
            }
            for i in s..=e {
                let line = lines[i];
                let lower = line.to_lowercase();
                for method in [".join(", ".push("] {
                    for (pos, _) in line.match_indices(method) {
                        let Some(arg) = Self::extract_arg_at(line, pos + method.len(), 0) else {
                            continue;
                        };
                        let arg_t = arg.trim();
                        if arg_t.starts_with('"') || arg_t.starts_with("r\"") || arg_t.starts_with("r#") {
                            continue;
                        }
                        let call_prefix = line[..pos].to_lowercase();
                        if slice_recv_cues.iter().any(|c| call_prefix.contains(c)) {
                            continue;
                        }
                        let has_path_recv = path_recv_cues.iter().any(|c| call_prefix.contains(c))
                            || call_prefix.contains("path::new")
                            || call_prefix.contains("pathbuf::");
                        if method == ".push(" && !has_path_recv {
                            continue;
                        }
                        if !has_path_recv && !lower_block.contains("path::new") && !lower_block.contains("pathbuf") {
                            continue;
                        }
                        let arg_lower = arg_t.to_lowercase();
                        let fn_header = lines[s].to_lowercase();
                        let untrusted = untrusted_cues
                            .iter()
                            .any(|c| arg_lower.contains(c) || fn_header.contains(c) || lower.contains(c));
                        if !untrusted {
                            continue;
                        }
                        let method_name = &method[..method.len() - 1];
                        Self::push_rule(
                            out,
                            file_path,
                            i + 1,
                            "AETHER-RUST-PATH-JOIN-PREFIX-WIPE",
                            "AETHER-PATH-008 / PATH-JOIN-ABSOLUTE-OVERWRITE",
                            "CRITICAL",
                            format!(
                                "📂 [AETHER-PATH-008] PATH_JOIN_PREFIX_WIPE : `{}({})` sur entrée non confinée : si l'entrée commence par `/` ou `\\\\?\\`, Path::join/push efface entièrement la racine de base sans `..`.",
                                method_name, arg_t
                            ),
                            &arg,
                            "PathPrefixOverwrite",
                            "Vérifier `!input.is_absolute() && !input.has_root()`, filtrer `components()` pour n'accepter que `Component::Normal`, puis vérifier `.canonicalize()?.starts_with(&base_canonical)`.",
                        );
                    }
                }
            }
        }
    }

    fn audit_rust_assert_unwindsafe(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        if !content.contains("AssertUnwindSafe(") {
            return;
        }
        let lines: Vec<&str> = content.lines().collect();
        let mut_cues = ["&mut ", ".borrow_mut(", "ptr::write", "+=", "-=", "*=", ".push(", ".insert(", ".remove(", ".clear("];
        for (idx, line) in lines.iter().enumerate() {
            if !line.contains("AssertUnwindSafe(") {
                continue;
            }
            let end = Self::find_call_statement_end(&lines, idx).min(lines.len().saturating_sub(1));
            let win_start = idx.saturating_sub(2);
            let win_end = (end + 4).min(lines.len().saturating_sub(1));
            let window: String = lines[win_start..=win_end].join("\n");
            let slice: String = lines[idx..=end].join("\n");
            let has_mut_borrow = slice.contains("&mut ")
                || mut_cues.iter().any(|m| slice.contains(m))
                || window.contains("&mut ");
            let in_catch = window.contains("catch_unwind");
            if has_mut_borrow && in_catch {
                Self::push_rule(
                    out,
                    file_path,
                    idx + 1,
                    "AETHER-RUST-ASSERT-UNWINDSAFE-STATE-TORN",
                    "AETHER-PANIC-009 / ASSERT-UNWINDSAFE-MUT-CORRUPTION",
                    "HIGH",
                    "⚠️ [AETHER-PANIC-009] ASSERT_UNWINDSAFE_TORN_STATE : `AssertUnwindSafe` autour d'un état mutable capturé dans `catch_unwind` laisse l'état partiellement muté (déchiré) exploitable après panique.".to_string(),
                    "AssertUnwindSafe(&mut / mutating closure)",
                    "UnwindSafeStateCorruption",
                    "Éviter `AssertUnwindSafe` sur des états mutables critiques ou appliquer un pattern transactionnel/rollback (Mutex poison ou copie atomique).",
                );
            }
        }
    }

    fn audit_rust_utf8_lossy_smuggling(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        if !content.contains("from_utf8_lossy(") {
            return;
        }
        let lines: Vec<&str> = content.lines().collect();
        let fn_scopes = Self::collect_brace_scopes(&lines, |t| Self::has_token(t, "fn"));
        let sec_cues = [
            "verify", "hmac", "signature", "token", "auth", "password", "passwd",
            "secret", "sanitiz", "escape", "allowlist", "whitelist", "claim",
            "jwt", "nonce", "digest", "rbac", "acl", "permission",
        ];
        for (s, e) in fn_scopes {
            let block: String = lines[s..=e].join("\n");
            if !block.contains("from_utf8_lossy(") {
                continue;
            }
            let lower_block = block.to_lowercase();
            let rejects_invalid = block.contains("REPLACEMENT_CHARACTER")
                || lower_block.contains("fffd")
                || block.contains("from_utf8(");
            if rejects_invalid || !sec_cues.iter().any(|c| lower_block.contains(c)) {
                continue;
            }
            if let Some(hit) = (s..=e).find(|&i| lines[i].contains("from_utf8_lossy(")) {
                Self::push_rule(
                    out,
                    file_path,
                    hit + 1,
                    "AETHER-RUST-UTF8-LOSSY-SMUGGLING",
                    "AETHER-NORM-010 / UTF8-LOSSY-REPLACEMENT-COLLISION",
                    "HIGH",
                    "🔤 [AETHER-NORM-010] UTF8_LOSSY_SMUGGLING : `from_utf8_lossy()` en contexte de vérification/auth/sanitisation convertit plusieurs séquences d'octets invalides vers U+FFFD sans rejet.".to_string(),
                    "String::from_utf8_lossy",
                    "LossyUtf8Collision",
                    "Utiliser `std::str::from_utf8(bytes)?` pour rejeter strictement les séquences non-UTF8 avant hachage, signature ou validation.",
                );
            }
        }
    }

    fn extract_rust_regex_literal(line: &str) -> Option<&str> {
        let idx = line.find("Regex::new(").or_else(|| line.find("RegexBuilder::new("))?;
        let after = &line[idx..];
        let open_paren = after.find('(')?;
        let arg = after[open_paren + 1..].trim_start();
        if let Some(rest) = arg.strip_prefix("r#\"") {
            let end = rest.find("\"#")?;
            return Some(&rest[..end]);
        }
        if let Some(rest) = arg.strip_prefix("r\"") {
            let end = rest.find('"')?;
            return Some(&rest[..end]);
        }
        if let Some(rest) = arg.strip_prefix('"') {
            let bytes = rest.as_bytes();
            let mut esc = false;
            for (i, &b) in bytes.iter().enumerate() {
                if esc {
                    esc = false;
                } else if b == b'\\' {
                    esc = true;
                } else if b == b'"' {
                    return Some(&rest[..i]);
                }
            }
        }
        None
    }

    fn is_strictly_anchored_regex(pat: &str) -> bool {
        let trimmed = pat.trim();
        let has_strict = trimmed.starts_with(r"\A") && trimmed.ends_with(r"\z");
        if has_strict {
            return true;
        }
        let multi = trimmed.contains("(?m)") || trimmed.contains("(?ms");
        if multi {
            return false;
        }
        trimmed.starts_with('^') && trimmed.ends_with('$')
    }

    fn audit_rust_unanchored_regex_gate(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let no_comments = lexer::mask_comments_only(content, Lang::Rust);
        if !no_comments.contains("Regex::new(") && !no_comments.contains("RegexBuilder::new(") {
            return;
        }
        if !no_comments.contains(".is_match(") {
            return;
        }
        let sec_cues = [
            "allow", "origin", "host", "domain", "url", "uri", "redirect",
            "role", "auth", "admin", "perm", "token", "whitelist", "trusted",
            "cors", "csrf", "ssrf", "valid", "sanitiz", "safe",
        ];
        let lines: Vec<&str> = no_comments.lines().collect();
        for (idx, &line) in lines.iter().enumerate() {
            let Some(pat) = Self::extract_rust_regex_literal(line) else {
                continue;
            };
            if Self::is_strictly_anchored_regex(pat) {
                continue;
            }
            let win_s = idx.saturating_sub(2);
            let win_e = (idx + 6).min(lines.len().saturating_sub(1));
            let ctx = lines[win_s..=win_e].join("\n").to_lowercase();
            if !sec_cues.iter().any(|c| ctx.contains(c)) {
                continue;
            }
            Self::push_rule(
                out,
                file_path,
                idx + 1,
                "AETHER-RUST-UNANCHORED-REGEX-GATE",
                "AETHER-CTRL-011 / REGEX-SUBSTRING-IS-MATCH-BYPASS",
                "HIGH",
                format!(
                    "🎯 [AETHER-CTRL-011] UNANCHORED_REGEX_GATE : Regex `{}` utilisée dans un contrôle d'allowlist/sécurité sans ancres strictes (\\A.. \\z) ou avec (?m) : `is_match` matche n'importe quelle sous-chaîne.",
                    pat
                ),
                pat,
                "UnanchoredRegexSecurityGate",
                "Encadrer la regex par `^...$` (sans `(?m)`) ou préférablement `\\A...\\z` pour forcer une correspondance sur toute la chaîne.",
            );
        }
    }

    fn audit_rust_relaxed_atomic_gate(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        if !content.contains("Ordering::Relaxed") {
            return;
        }
        let ops = [".load(", ".store(", ".swap(", ".compare_exchange(", ".compare_exchange_weak("];
        let sec_idents = [
            "auth", "admin", "init", "ready", "locked", "unlocked", "sealed",
            "verified", "valid", "priv", "perm", "role", "revoked", "active",
            "allowed", "trusted", "bypass", "superuser",
        ];
        let noise_cues = ["count", "counter", "metric", "stats", "bytes", "total", "dropped", "requests_"];
        for (idx, line) in content.lines().enumerate() {
            if !line.contains("Ordering::Relaxed") || !ops.iter().any(|op| line.contains(op)) {
                continue;
            }
            let lower = line.to_lowercase();
            if noise_cues.iter().any(|n| lower.contains(n)) {
                continue;
            }
            if !sec_idents.iter().any(|s| lower.contains(s)) {
                continue;
            }
            Self::push_rule(
                out,
                file_path,
                idx + 1,
                "AETHER-RUST-RELAXED-ATOMIC-SECURITY-GATE",
                "AETHER-MEM-012 / WEAK-RELAXED-ATOMIC-SECURITY-BARRIER",
                "HIGH",
                "⚡ [AETHER-MEM-012] RELAXED_ATOMIC_BARRIER : `Ordering::Relaxed` utilisé sur un drapeau atomique d'authentification, permission ou initialisation (absence de garantie happens-before sur ARM64/RISC-V).".to_string(),
                "Ordering::Relaxed",
                "WeakAtomicMemoryOrdering",
                "Utiliser `Ordering::Acquire` en lecture, `Ordering::Release` en écriture et `Ordering::AcqRel`/`SeqCst` sur compare_exchange.",
            );
        }
    }

    // -----------------------------------------------------------------------
    // 6 NOUVELLES PÉPITES SÉMANTIQUES PHP / ZEND ENGINE
    // -----------------------------------------------------------------------

    fn audit_php_loose_in_array_bool(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let lower_all = content.to_lowercase();
        if !lower_all.contains("in_array(") && !lower_all.contains("array_search(") {
            return;
        }
        let sec_cues = [
            "role", "perm", "admin", "allow", "whitelist", "blacklist", "action",
            "algo", "alg", "cipher", "hash", "scope", "group", "tier", "ext",
            "mime", "method", "cmd", "token", "auth", "$_get", "$_post",
            "$_request", "$_cookie", "json_decode", "page", "type",
        ];
        let lines: Vec<&str> = content.lines().collect();
        for (idx, &line) in lines.iter().enumerate() {
            let lower = line.to_lowercase();
            let call = if lower.contains("in_array(") {
                "in_array"
            } else if lower.contains("array_search(") {
                "array_search"
            } else {
                continue;
            };
            let end = Self::find_call_statement_end(&lines, idx).min(lines.len().saturating_sub(1));
            let stmt = lines[idx..=end].join(" ");
            let strict_arg = Self::extract_balanced_call_arg(&stmt, call, 2)
                .map(|s| s.trim().trim_start_matches('\\').to_lowercase());
            if matches!(strict_arg.as_deref(), Some("true")) {
                continue;
            }
            let win_s = idx.saturating_sub(2);
            let win_e = (end + 2).min(lines.len().saturating_sub(1));
            let ctx = lines[win_s..=win_e].join("\n").to_lowercase();
            if !sec_cues.iter().any(|c| ctx.contains(c)) {
                continue;
            }
            Self::push_rule(
                out,
                file_path,
                idx + 1,
                "AETHER-PHP-LOOSE-INARRAY-BOOL-BYPASS",
                "AETHER-ZEND-007 / PHP8-INARRAY-BOOL-TRUE-JUGGLING",
                "CRITICAL",
                format!(
                    "🔓 [AETHER-ZEND-007] LOOSE_{} : `{}(..., ...)` sans 3e paramètre `true` reste vulnérable au type juggling PHP 8 (bool `true` ou cast numérique sur allowlist/rôles).",
                    call.to_uppercase(),
                    call
                ),
                call,
                "PhpLooseInArrayJuggling",
                "Passer obligatoirement `true` en 3e argument : `in_array($val, $allowed, true)` / `array_search($val, $allowed, true)`.",
            );
        }
    }

    fn audit_php_parse_url_differential_ssrf(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let lower_all = content.to_lowercase();
        if !lower_all.contains("parse_url(") {
            return;
        }
        let net_sinks = [
            "curl_init", "curl_exec", "curl_setopt", "file_get_contents(",
            "fopen(", "stream_socket_client(", "fsockopen(", "guzzle", "http::",
        ];
        if !net_sinks.iter().any(|s| lower_all.contains(s)) {
            return;
        }
        let lines: Vec<&str> = content.lines().collect();
        let scopes = Self::collect_brace_scopes(&lines, |t| {
            Self::has_token(&t.to_lowercase(), "function")
        });
        let targets: Vec<(usize, usize)> = if scopes.is_empty() {
            vec![(0, lines.len().saturating_sub(1))]
        } else {
            scopes
        };
        for (s, e) in targets {
            let block = lines[s..=e].join("\n").to_lowercase();
            if !block.contains("parse_url(") || !net_sinks.iter().any(|k| block.contains(k)) {
                continue;
            }
            let has_ip_pinning = (block.contains("gethostbyname")
                || block.contains("dns_get_record")
                || block.contains("curlopt_resolve"))
                && block.contains("filter_flag_no_priv_range");
            let follows_redirects = block.contains("curlopt_followlocation")
                && !block.contains("curlopt_redir_protocols");
            if has_ip_pinning && !follows_redirects {
                continue;
            }
            if let Some(hit) = (s..=e).find(|&i| lines[i].to_lowercase().contains("parse_url(")) {
                Self::push_rule(
                    out,
                    file_path,
                    hit + 1,
                    "AETHER-PHP-PARSE-URL-DIFFERENTIAL-SSRF",
                    "AETHER-ZEND-008 / PARSE-URL-LIBCURL-HOST-DIFFERENTIAL",
                    "CRITICAL",
                    "🌐 [AETHER-ZEND-008] PARSE_URL_LIBCURL_SSRF : Validation d'URL via `parse_url()` combinée à un fetch réseau sans épinglage IP post-DNS (`FILTER_FLAG_NO_PRIV_RANGE` + `CURLOPT_RESOLVE`) ou avec redirection ouverte.".to_string(),
                    "parse_url() + outbound HTTP",
                    "UrlParserDifferentialSsrf",
                    "Résoudre l'IP avant requête, rejeter `FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`, désactiver `CURLOPT_FOLLOWLOCATION` et épingler l'IP avec `CURLOPT_RESOLVE`.",
                );
            }
        }
    }

    fn audit_php_escapeshellcmd_flag_rce(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let lower_all = content.to_lowercase();
        if !lower_all.contains("escapeshellcmd(") {
            return;
        }
        let exec_sinks = ["exec(", "system(", "passthru(", "shell_exec(", "proc_open(", "popen(", "`"];
        let has_exec = exec_sinks.iter().any(|s| lower_all.contains(s));
        for (idx, line) in content.lines().enumerate() {
            let lower = line.to_lowercase();
            if !lower.contains("escapeshellcmd(") {
                continue;
            }
            if !has_exec && !lower.contains('.') && !lower.contains('$') {
                continue;
            }
            Self::push_rule(
                out,
                file_path,
                idx + 1,
                "AETHER-PHP-ESCAPESHELLCMD-FLAG-RCE",
                "AETHER-ZEND-009 / ESCAPESHELLCMD-ARGUMENT-FLAG-INJECTION",
                "CRITICAL",
                "🐚 [AETHER-ZEND-009] ESCAPESHELLCMD_FLAG_RCE : `escapeshellcmd()` autorise les espaces et les drapeaux CLI (`-o`, `--checkpoint-action=...`), permettant l'injection d'arguments et l'exécution arbitraire.".to_string(),
                "escapeshellcmd()",
                "ShellArgumentFlagInjection",
                "Ne jamais utiliser `escapeshellcmd()` sur des commandes contenant des arguments utilisateur : isoler chaque argument avec `escapeshellarg()` ou `proc_open($argvArray, ...)`.",
            );
        }
    }

    fn audit_php_json_depth_null_failopen(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let lower_all = content.to_lowercase();
        if !lower_all.contains("json_decode(") {
            return;
        }
        if lower_all.contains("json_last_error(") || lower_all.contains("json_validate(") {
            return;
        }
        let sec_cues = [
            "$_post", "$_get", "$_request", "$_cookie", "php://input", "header",
            "token", "jwt", "claim", "webhook", "sig", "auth", "role", "perm",
            "payload", "body", "request", "raw",
        ];
        let lines: Vec<&str> = content.lines().collect();
        for (idx, &line) in lines.iter().enumerate() {
            let lower = line.to_lowercase();
            if !lower.contains("json_decode(") {
                continue;
            }
            let end = Self::find_call_statement_end(&lines, idx).min(lines.len().saturating_sub(1));
            let stmt = lines[idx..=end].join(" ").to_lowercase();
            if stmt.contains("json_throw_on_error") {
                continue;
            }
            let prev_s = idx.saturating_sub(4);
            let next_e = (end + 6).min(lines.len().saturating_sub(1));
            let pre_ctx = lines[prev_s..=end].join("\n").to_lowercase();
            if !sec_cues.iter().any(|c| pre_ctx.contains(c)) {
                continue;
            }
            let post_ctx = lines[idx..=next_e].join("\n").to_lowercase();
            let validates_null = post_ctx.contains("=== null")
                || post_ctx.contains("!== null")
                || post_ctx.contains("is_null(")
                || post_ctx.contains("!is_array(");
            if validates_null {
                continue;
            }
            Self::push_rule(
                out,
                file_path,
                idx + 1,
                "AETHER-PHP-JSON-DEPTH-NULL-FAILOPEN",
                "AETHER-ZEND-010 / JSON-DECODE-DEPTH512-SILENT-NULL",
                "HIGH",
                "🧩 [AETHER-ZEND-010] JSON_DECODE_SILENT_NULL : `json_decode()` sans `JSON_THROW_ON_ERROR` ni vérification d'erreur renvoie silencieusement `null` au-delà de depth=512 ou sur UTF-8 invalide.".to_string(),
                "json_decode() without JSON_THROW_ON_ERROR",
                "JsonDecodeSilentNullFailOpen",
                "Passer `JSON_THROW_ON_ERROR` en drapeau (`json_decode($raw, true, 512, JSON_THROW_ON_ERROR)`) ou valider d'abord avec `json_validate()`.",
            );
        }
    }

    fn audit_php_pdo_emulated_prepares(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let no_comments = lexer::mask_comments_only(content, Lang::Php);
        let lower_all = no_comments.to_lowercase();
        if !lower_all.contains("new pdo(") && !lower_all.contains("new \\pdo(") {
            return;
        }
        let lines: Vec<&str> = no_comments.lines().collect();
        for (idx, &line) in lines.iter().enumerate() {
            let lower = line.to_lowercase();
            if !lower.contains("new pdo(") && !lower.contains("new \\pdo(") {
                continue;
            }
            let end = Self::find_call_statement_end(&lines, idx).min(lines.len().saturating_sub(1));
            let win_s = idx.saturating_sub(8);
            let win_e = (end + 10).min(lines.len().saturating_sub(1));
            let window = lines[win_s..=win_e].join("\n").to_lowercase();
            let stmt = lines[idx..=end].join(" ").to_lowercase();
            let explicit_enabled = window.contains("attr_emulate_prepares => true")
                || window.contains("attr_emulate_prepares=>true")
                || window.contains("attr_emulate_prepares, true")
                || window.contains("attr_emulate_prepares => 1");
            if explicit_enabled {
                Self::push_rule(
                    out,
                    file_path,
                    idx + 1,
                    "AETHER-PHP-PDO-EMULATED-PREPARES-SMUGGLING",
                    "AETHER-ZEND-011 / PDO-CLIENT-EMULATED-PREPARE-SMUGGLING",
                    "HIGH",
                    "🗄️ [AETHER-ZEND-011] PDO_EMULATED_PREPARES_ENABLED : `ATTR_EMULATE_PREPARES` explicitement activé sur PDO — désactive le protocole binaire préparé et autorise les multi-requêtes/smuggling.".to_string(),
                    "PDO::ATTR_EMULATE_PREPARES => true",
                    "PdoClientEmulatedPrepares",
                    "Désactiver l'émulation : `[PDO::ATTR_EMULATE_PREPARES => false, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]`.",
                );
                continue;
            }
            if stmt.contains("sqlite:") {
                continue;
            }
            let has_disabled = lower_all.contains("attr_emulate_prepares => false")
                || lower_all.contains("attr_emulate_prepares=>false")
                || lower_all.contains("attr_emulate_prepares, false")
                || lower_all.contains("attr_emulate_prepares => 0");
            if !has_disabled && (stmt.contains("mysql:") || stmt.contains("pgsql:") || stmt.contains('$')) {
                Self::push_rule(
                    out,
                    file_path,
                    idx + 1,
                    "AETHER-PHP-PDO-EMULATED-PREPARES-SMUGGLING",
                    "AETHER-ZEND-011 / PDO-CLIENT-EMULATED-PREPARE-SMUGGLING",
                    "HIGH",
                    "🗄️ [AETHER-ZEND-011] PDO_EMULATED_PREPARES_DEFAULT : Instanciation `new PDO(...)` sans `PDO::ATTR_EMULATE_PREPARES => false` (émulation client active par défaut, vulnérable au parser differential MySQL).".to_string(),
                    "new PDO() default emulated prepares",
                    "PdoClientEmulatedPrepares",
                    "Passer `PDO::ATTR_EMULATE_PREPARES => false` dans le 4e argument `$options` de `new PDO(...)` ou via `$pdo->setAttribute(...)`.",
                );
            }
        }
    }

    fn php_is_dangerous_curly_expr(expr: &str, is_nested_double_brace: bool) -> bool {
        let lower = expr.to_lowercase();
        let superglobals = [
            "$_get", "$_post", "$_request", "$_cookie", "$_server", "$globals",
        ];
        if superglobals.iter().any(|sg| lower.contains(sg)) {
            return true;
        }
        if is_nested_double_brace && expr.contains('(') {
            return true;
        }
        expr.contains('(') && (expr.starts_with('$') || expr.contains("->") || expr.contains('['))
    }

    fn audit_php_curly_var_interpolation(
        file_path: &str,
        content: &str,
        out: &mut Vec<LinterViolation>,
    ) {
        let no_comments = lexer::mask_comments_only(content, Lang::Php);
        if !no_comments.contains("${") {
            return;
        }
        let bytes = no_comments.as_bytes();
        let len = bytes.len();
        let mut i = 0usize;
        let mut line_no = 1usize;
        let mut at_line_start = true;
        let mut in_sq = false;
        let mut in_dq = false;
        let mut escaped = false;
        let mut heredoc: Option<(String, bool)> = None;

        while i < len {
            let b = bytes[i];
            if b == b'\n' {
                line_no += 1;
                at_line_start = true;
                escaped = false;
                i += 1;
                continue;
            }
            if let Some((ref tag, is_nowdoc)) = heredoc {
                if at_line_start {
                    let line_end = bytes[i..].iter().position(|&c| c == b'\n').map_or(len, |p| i + p);
                    let trimmed = no_comments[i..line_end].trim().trim_end_matches(';').trim();
                    if trimmed == tag {
                        heredoc = None;
                        i = line_end;
                        at_line_start = false;
                        continue;
                    }
                }
                at_line_start = false;
                if is_nowdoc {
                    i += 1;
                    continue;
                }
            }
            at_line_start = false;

            if escaped {
                escaped = false;
                i += 1;
                continue;
            }
            if in_sq {
                if b == b'\\' {
                    escaped = true;
                } else if b == b'\'' {
                    in_sq = false;
                }
                i += 1;
                continue;
            }
            if !in_dq && heredoc.is_none() {
                if b == b'\'' {
                    in_sq = true;
                } else if b == b'"' {
                    in_dq = true;
                } else if bytes[i..].starts_with(b"<<<") {
                    let line_end = bytes[i..].iter().position(|&c| c == b'\n').map_or(len, |p| i + p);
                    let spec = no_comments[i + 3..line_end].trim();
                    let is_nowdoc = spec.starts_with('\'');
                    let tag: String = spec
                        .trim_matches(|c| c == '\'' || c == '"')
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !tag.is_empty() {
                        heredoc = Some((tag, is_nowdoc));
                        i = line_end;
                        continue;
                    }
                }
                i += 1;
                continue;
            }

            if b == b'\\' {
                escaped = true;
                i += 1;
                continue;
            }
            if in_dq && b == b'"' {
                in_dq = false;
                i += 1;
                continue;
            }
            let is_nested = bytes[i..].starts_with(b"{${");
            let is_dollar_brace = !is_nested && bytes[i..].starts_with(b"${");
            if is_nested || is_dollar_brace {
                let expr_start = i + if is_nested { 3 } else { 2 };
                let mut depth = if is_nested { 2i32 } else { 1i32 };
                let mut j = expr_start;
                while j < len && depth > 0 {
                    match bytes[j] {
                        b'{' => depth += 1,
                        b'}' => depth -= 1,
                        b'\n' => break,
                        _ => {}
                    }
                    j += 1;
                }
                let expr_end = if depth == 0 { j.saturating_sub(1) } else { j };
                let expr = &no_comments[expr_start..expr_end];
                if Self::php_is_dangerous_curly_expr(expr, is_nested) {
                    Self::push_rule(
                        out,
                        file_path,
                        line_no,
                        "AETHER-PHP-CURLY-VAR-INTERPOLATION-RCE",
                        "AETHER-ZEND-012 / PHP-COMPLEX-CURLY-SYNTAX-EXEC",
                        "CRITICAL",
                        "💥 [AETHER-ZEND-012] PHP_COMPLEX_CURLY_INTERPOLATION_RCE : Syntaxe `{${func()}}` ou `${$_SUPERGLOBAL}` détectée dans une chaîne PHP — déclenche l'évaluation dynamique de fonction ou de variable-variable.".to_string(),
                        "complex curly string interpolation",
                        "PhpComplexCurlyInterpolationRce",
                        "Supprimer toute syntaxe `{${...}}` / `${$var}` des chaînes interpolées et valider les entrées explicitement.",
                    );
                }
                i = j;
                continue;
            }
            i += 1;
        }
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
