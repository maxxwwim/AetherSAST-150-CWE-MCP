use crate::linter::{CveRuleDef, LinterViolation};

pub struct ZigSecurityRules;

impl ZigSecurityRules {
    /// Checks whether the file is a Zig source file (.zig).
    pub fn is_zig_file(file_path: &str) -> bool {
        let p = file_path.to_lowercase();
        p.ends_with(".zig")
    }

    /// Complete catalog of the 15 Zig production CWE rules.
    pub fn definitions() -> Vec<CveRuleDef> {
        vec![
            // 1. CWE-416: Use After Free
            CveRuleDef {
                rule_id: "CVE-ZIG-USE-AFTER-FREE".to_string(),
                cve_id: "CWE-416 / USE-AFTER-FREE-ALLOCATOR".to_string(),
                name: "Utilisation ou Double Libération de Mémoire après Free (Use-After-Free / Double-Free)".to_string(),
                category: "Zig / Memory Safety".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Désallocation de mémoire dynamique via allocator.free(slice), allocator.destroy(ptr) ou arena.deinit() suivie d'un déréférencement (ptr.*), indexation (slice[i]), passage à une fonction ou ré-exécution de free dans la même portée. Détecte également le renvoi d'adresses de buffers alloués sur la pile locale (stack-use-after-return).".to_string(),
                default_enabled: true,
            },
            // 2. CWE-703 / CWE-391: Unhandled Error Union
            CveRuleDef {
                rule_id: "CVE-ZIG-UNHANDLED-ERROR-UNION".to_string(),
                cve_id: "CWE-703 / UNHANDLED-ERROR-UNION".to_string(),
                name: "Ignorance Non Sécurisée d'Union d'Erreur (Unhandled Error Union / catch unreachable)".to_string(),
                category: "Zig / Error Handling".to_string(),
                severity: "HIGH".to_string(),
                description: "Ignorance d'une valeur de retour d'union d'erreur via '_ = func()' sans 'try' ni 'catch', ou utilisation de 'catch unreachable' sur des opérations I/O, réseau, d'allocation ou de parsing. En mode ReleaseFast, 'catch unreachable' provoque un comportement indéfini (UB).".to_string(),
                default_enabled: true,
            },
            // 3. CWE-190: Integer Overflow / Wrapping Arithmetic
            CveRuleDef {
                rule_id: "CVE-ZIG-INTEGER-OVERFLOW-WRAPPING".to_string(),
                cve_id: "CWE-190 / INTEGER-OVERFLOW-WRAPPING".to_string(),
                name: "Arithmétique Enveloppante Non Bornée sur Tailles ou Indices (Wrapping Arithmetic Overflow)".to_string(),
                category: "Zig / Integer Safety".to_string(),
                severity: "HIGH".to_string(),
                description: "Utilisation d'opérateurs arithmétiques enveloppants (+%, -%, *%) ou @truncate / @intCast non vérifiés sur des grandeurs sensibles (tailles de buffer, indices, montants, allocations mémoire). En mode ReleaseFast, le dépassement non vérifié mène à des corruptions mémoire ou allocations tronquées.".to_string(),
                default_enabled: true,
            },
            // 4. CWE-843: Insecure Pointer Cast / Type Confusion
            CveRuleDef {
                rule_id: "CVE-ZIG-INSECURE-POINTER-CAST".to_string(),
                cve_id: "CWE-843 / INSECURE-POINTER-TYPE-CONFUSION".to_string(),
                name: "Cast de Pointeur Incompatible & Désaligné (Insecure Pointer Cast / Type Confusion)".to_string(),
                category: "Zig / Memory Safety".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Conversion de type de pointeur non sécurisée via @ptrCast ou @alignCast sur des tampons d'octets bruts ou des adresses sans vérification de taille et d'alignement mémoire : risque d'align fault matériel (SIGBUS) ou réinterprétation invalide de structure.".to_string(),
                default_enabled: true,
            },
            // 5. CWE-457: Uninitialized Memory
            CveRuleDef {
                rule_id: "CVE-ZIG-UNINITIALIZED-MEMORY".to_string(),
                cve_id: "CWE-457 / UNINITIALIZED-MEMORY-ACCESS".to_string(),
                name: "Lecture ou Transmission de Mémoire Non Initialisée (Uninitialized Variable / undefined)".to_string(),
                category: "Zig / Memory Safety".to_string(),
                severity: "HIGH".to_string(),
                description: "Déclaration d'un tampon ou d'une structure avec '= undefined' suivi d'une lecture, écriture réseau ou transmission avant toute initialisation explicite : fuite de secrets de la pile ou données non déterministes.".to_string(),
                default_enabled: true,
            },
            // 6. CWE-119 / CWE-120: Buffer Overrun & C-Interop
            CveRuleDef {
                rule_id: "CVE-ZIG-BUFFER-OVERRUN-C-INTEROP".to_string(),
                cve_id: "CWE-119 / C-INTEROP-BUFFER-OVERRUN".to_string(),
                name: "Dépassement de Tampon C-Interop & Pointeur Non Terminé par Zéro (Buffer Overrun / Non-Sentinel C-String)".to_string(),
                category: "Zig / C-Interop & Bounds".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Passage d'un pointeur de slice standard ([]const u8) sans sentinelle nulle ([*:0]const u8) à des fonctions de l'ABI C (printf, strlen, etc.), déréférencement aveugle via @ptrFromInt, ou appel à des fonctions C obsolètes non sécurisées (c.strcpy, c.sprintf, c.gets).".to_string(),
                default_enabled: true,
            },
            // 7. CWE-134: Uncontrolled C Format String
            CveRuleDef {
                rule_id: "CVE-ZIG-UNPROTECTED-C-FORMAT-STRING".to_string(),
                cve_id: "CWE-134 / UNPROTECTED-C-FORMAT-STRING".to_string(),
                name: "Chaîne de Format Non Contrôlée en Interop C (Uncontrolled Format String in C-ABI)".to_string(),
                category: "Zig / C-Interop".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Passage d'une chaîne dynamique ou contrôlée par l'utilisateur comme paramètre de formatage direct à des fonctions C (c.printf, std.c.printf, c.snprintf, c.fprintf, c.syslog) sans spécificateur littéral : divulgation de mémoire et écriture arbitraire via %n.".to_string(),
                default_enabled: true,
            },
            // 8. CWE-401: Raw Allocator Memory Leak
            CveRuleDef {
                rule_id: "CVE-ZIG-RAW-ALLOCATOR-LEAK".to_string(),
                cve_id: "CWE-401 / RAW-ALLOCATOR-MEMORY-LEAK".to_string(),
                name: "Fuite de Ressource Mémoire Allocateur (Missing Deallocation / Memory Leak)".to_string(),
                category: "Zig / Resource Management".to_string(),
                severity: "HIGH".to_string(),
                description: "Allocation de mémoire sur le tas via allocator.alloc() ou allocator.create() sans 'defer allocator.free()' ou 'errdefer allocator.free()' correspondant et sans que la ressource ne soit retournée par la fonction : épuisement progressif de la mémoire (DoS).".to_string(),
                default_enabled: true,
            },
            // 9. CWE-78: OS Command Injection via std.process.Child
            CveRuleDef {
                rule_id: "CVE-ZIG-COMMAND-INJECTION".to_string(),
                cve_id: "CWE-78 / OS-COMMAND-INJECTION-CHILD".to_string(),
                name: "Injection de Commande Système OS via std.process.Child & Shell (-c / /c)".to_string(),
                category: "Zig / Injection".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Exécution d'un sous-processus via std.process.Child.init ou std.process.Child.run invoquant un interpréteur shell (/bin/sh -c, bash -c, cmd.exe /c, powershell) avec une chaîne dynamique non filtrée : permet l'exécution de commandes arbitraires (RCE).".to_string(),
                default_enabled: true,
            },
            // 10. CWE-22: Path Traversal via Unconfined std.fs
            CveRuleDef {
                rule_id: "CVE-ZIG-PATH-TRAVERSAL".to_string(),
                cve_id: "CWE-22 / PATH-TRAVERSAL-UNCONFINED-FS".to_string(),
                name: "Traversée de Répertoire & Accès Fichier Non Confiné (std.fs.path.join / openFile)".to_string(),
                category: "Zig / File Security".to_string(),
                severity: "HIGH".to_string(),
                description: "Construction de chemin via std.fs.path.join ou ouverture directe via std.fs.cwd().openFile / deleteTree sur une entrée externe sans filtrage des séquences '..' ni isolation par std.fs.path.basename.".to_string(),
                default_enabled: true,
            },
            // 11. CWE-676: @setRuntimeSafety(false) Memory Safety Bypass
            CveRuleDef {
                rule_id: "CVE-ZIG-RUNTIME-SAFETY-DISABLED".to_string(),
                cve_id: "CWE-676 / SET-RUNTIME-SAFETY-DISABLED-UB".to_string(),
                name: "Désactivation Explicite des Gardes-Fous d'Exécution (@setRuntimeSafety(false))".to_string(),
                category: "Zig / Memory Safety".to_string(),
                severity: "HIGH".to_string(),
                description: "Appel à @setRuntimeSafety(false) désactivant les vérifications de bornes de tranches (bounds checking), de débordement arithmétique et d'union active : transforme tout accès hors bornes en corruption mémoire silencieuse (UB).".to_string(),
                default_enabled: true,
            },
            // 12. CWE-562: Return of Stack Variable Address (Stack Use-After-Return)
            CveRuleDef {
                rule_id: "CVE-ZIG-STACK-ADDRESS-RETURN".to_string(),
                cve_id: "CWE-562 / STACK-USE-AFTER-RETURN-DANGLING".to_string(),
                name: "Fuite de Pointeur sur Pile Locale (Return of Stack Buffer Address / Dangling Slice)".to_string(),
                category: "Zig / Memory Safety".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Renvoi de l'adresse (&local_buf) ou d'une tranche (local_buf[0..]) pointant vers un tableau alloué sur la pile locale de la fonction : la mémoire est invalidée dès le retour de fonction (Stack Use-After-Return).".to_string(),
                default_enabled: true,
            },
            // 13. CWE-295: Improper Certificate Validation in std.crypto.tls / http.Client
            CveRuleDef {
                rule_id: "CVE-ZIG-TLS-VERIFY-DISABLED".to_string(),
                cve_id: "CWE-295 / TLS-CERTIFICATE-VERIFY-BYPASS".to_string(),
                name: "Désactivation de la Vérification de Certificat TLS (std.http.Client / std.crypto.tls)".to_string(),
                category: "Zig / Cryptography & Network".to_string(),
                severity: "HIGH".to_string(),
                description: "Configuration d'une connexion TLS ou d'un client HTTP Zig désactivant la validation de la chaîne de certificats (tls_skip_verify = true, ca_bundle = .none, verify = .none), exposant aux interceptions Man-in-the-Middle (MitM).".to_string(),
                default_enabled: true,
            },
            // 14. CWE-338: Weak Non-Cryptographic PRNG for Secrets
            CveRuleDef {
                rule_id: "CVE-ZIG-WEAK-PRNG-CRYPTO".to_string(),
                cve_id: "CWE-338 / INSECURE-PRNG-DEFAULTPRNG".to_string(),
                name: "Génération de Secrets via PRNG Non Cryptographique (DefaultPrng / Xoroshiro128)".to_string(),
                category: "Zig / Cryptography & Network".to_string(),
                severity: "HIGH".to_string(),
                description: "Utilisation de std.rand.DefaultPrng ou Xoroshiro128 pour générer des jetons, clés, nonces ou sels cryptographiques : l'état interne de 128 bits est prédictible, contrairement à std.crypto.random (CSPRNG OS).".to_string(),
                default_enabled: true,
            },
            // 15. CWE-125: Unaligned or Out-of-Bounds SIMD @Vector Load
            CveRuleDef {
                rule_id: "CVE-ZIG-SIMD-VECTOR-UNALIGNED-OOB".to_string(),
                cve_id: "CWE-125 / SIMD-VECTOR-OUT-OF-BOUNDS".to_string(),
                name: "Chargement Vectoriel SIMD @Vector Non Aligné ou Sans Vérification de Bornes".to_string(),
                category: "Zig / Memory Safety".to_string(),
                severity: "HIGH".to_string(),
                description: "Conversion directe d'un pointeur de tranche vers un vecteur matériel @Vector(N, T) via @ptrCast sans @alignCast ni contrôle préalable de longueur (slice.len >= N), provoquant une lecture hors bornes ou une faute matérielle SIMD.".to_string(),
                default_enabled: true,
            },
        ]
    }

    /// Convenience audit function taking only file_path and content.
    pub fn audit(file_path: &str, content: &str) -> Vec<LinterViolation> {
        Self::audit_file(file_path, content, false, false)
    }

    /// Full static audit of a Zig source file.
    pub fn audit_file(
        file_path: &str,
        content: &str,
        is_test_file: bool,
        is_interface_or_types: bool,
    ) -> Vec<LinterViolation> {
        let mut violations = Vec::new();

        // Isolation: execute STRICTLY on Zig files
        if !Self::is_zig_file(file_path) || is_test_file || is_interface_or_types {
            return violations;
        }

        let lines: Vec<&str> = content.lines().collect();

        // Contextual analysis per function block
        let mut in_function = false;
        let mut fn_lines: Vec<(usize, &str)> = Vec::new();
        let mut brace_depth = 0i32;

        for (idx, &line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            // Detect function boundary
            if !in_function && (trimmed.contains("fn ") || trimmed.starts_with("pub fn ") || trimmed.starts_with("fn ")) {
                in_function = true;
                fn_lines.clear();
            }

            if in_function {
                fn_lines.push((line_no, line));
                for ch in line.chars() {
                    if ch == '{' {
                        brace_depth += 1;
                    } else if ch == '}' {
                        brace_depth -= 1;
                    }
                }
                if brace_depth <= 0 && !fn_lines.is_empty() {
                    // Function block complete - audit function-scoped rules
                    Self::audit_function_block(file_path, &fn_lines, &mut violations);
                    in_function = false;
                    brace_depth = 0;
                    fn_lines.clear();
                }
            }

            // -------------------------------------------------------------
            // Line-by-line single-statement evaluations
            // -------------------------------------------------------------

            // 2. CVE-ZIG-UNHANDLED-ERROR-UNION (CWE-703 / CWE-391)
            let is_discarded_assignment = trimmed.starts_with("_ = ") || trimmed.contains(" _ = ");
            if is_discarded_assignment {
                let fallible_ops = [
                    "file.write", "file.read", ".writeAll", ".readAll",
                    "allocator.alloc", "allocator.create",
                    "std.fs.", "openFile", "createFile", "deleteFile", "makeDir",
                    "std.net.", "tcpConnectToHost", "connect(", "listen(",
                    ".write(", ".read("
                ];
                let targets_fallible = fallible_ops.iter().any(|op| trimmed.contains(op));
                let has_handler = trimmed.contains("try ") || trimmed.contains("catch ");

                if targets_fallible && !has_handler {
                    violations.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: line_no,
                        rule_id: "CVE-ZIG-UNHANDLED-ERROR-UNION".to_string(),
                        cve_id: "CWE-703 / UNHANDLED-ERROR-UNION".to_string(),
                        severity: "HIGH".to_string(),
                        message: "🚨 [CWE-703] UNHANDLED-ERROR-UNION : Valeur de retour d'union d'erreur ignorée via '_ =' sans 'try' ni clause 'catch'. Les échecs d'E/S ou d'allocation seront silencieusement ignorés.".to_string(),
                        transmitted_data: Some("discarded_error_union".to_string()),
                        transmitted_type: Some("ErrorUnion (Unchecked Return Value)".to_string()),
                        remediation: "Propager l'erreur avec 'try' ou traiter le cas d'échec avec 'catch |err| { ... }'.".to_string(),
                    });
                }
            }

            if trimmed.contains("catch unreachable") {
                let risky_ops = ["std.net", "tcpConnect", "std.fs", "openFile", "createFile", "file.read", "file.write", "allocator.alloc", "connect("];
                if risky_ops.iter().any(|op| trimmed.contains(op)) {
                    violations.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: line_no,
                        rule_id: "CVE-ZIG-UNHANDLED-ERROR-UNION".to_string(),
                        cve_id: "CWE-703 / UNHANDLED-ERROR-UNION".to_string(),
                        severity: "HIGH".to_string(),
                        message: "🚨 [CWE-703] UNHANDLED-ERROR-UNION : Utilisation de 'catch unreachable' sur une opération faillible (réseau/fichier/allocateur). En mode ReleaseFast, cela provoque un comportement indéfini (UB).".to_string(),
                        transmitted_data: Some("catch_unreachable_call".to_string()),
                        transmitted_type: Some("ErrorUnion (Unreachable Trap)".to_string()),
                        remediation: "Gérer l'erreur explicitement via 'catch |err| { ... }' ou propager avec 'try'.".to_string(),
                    });
                }
            }

            // 3. CVE-ZIG-INTEGER-OVERFLOW-WRAPPING (CWE-190)
            let has_wrapping_op = trimmed.contains("+%") || trimmed.contains("-%") || trimmed.contains("*%");
            if has_wrapping_op && !trimmed.contains("@addWithOverflow") && !trimmed.contains("@subWithOverflow") && !trimmed.contains("@mulWithOverflow") {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-ZIG-INTEGER-OVERFLOW-WRAPPING".to_string(),
                    cve_id: "CWE-190 / INTEGER-OVERFLOW-WRAPPING".to_string(),
                    severity: "HIGH".to_string(),
                    message: "🚨 [CWE-190] INTEGER-OVERFLOW-WRAPPING : Arithmétique enveloppante non bornée (+%, -%, *%) sur calcul de taille ou indexation. Risque de dépassement d'entier et d'allocation sous-dimensionnée.".to_string(),
                    transmitted_data: Some("wrapping_arithmetic_expr".to_string()),
                    transmitted_type: Some("Integer (Unchecked Wrapping)".to_string()),
                    remediation: "Remplacer l'opérateur enveloppant par '@addWithOverflow' avec vérification du bit de dépassement ou un contrôle de bornes strict.".to_string(),
                });
            }

            // 4. CVE-ZIG-INSECURE-POINTER-CAST (CWE-843)
            let has_ptr_cast = trimmed.contains("@ptrCast(");
            if has_ptr_cast && !trimmed.contains("bytesAsValue") && !trimmed.contains("bytesAsSlice") {
                let targets_raw_ptr = trimmed.contains(".ptr") || trimmed.contains("@alignCast(");
                if targets_raw_ptr {
                    violations.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: line_no,
                        rule_id: "CVE-ZIG-INSECURE-POINTER-CAST".to_string(),
                        cve_id: "CWE-843 / INSECURE-POINTER-TYPE-CONFUSION".to_string(),
                        severity: "CRITICAL".to_string(),
                        message: "🚨 [CWE-843] INSECURE-POINTER-CAST : Cast de pointeur brut (@ptrCast/@alignCast) sur octets non validés sans contrôle de taille et d'alignement mémoire (risque de SIGBUS et type confusion).".to_string(),
                        transmitted_data: Some("raw_pointer_cast".to_string()),
                        transmitted_type: Some("Pointer (Incompatible / Unaligned Cast)".to_string()),
                        remediation: "Utiliser 'std.mem.bytesAsValue' ou 'std.mem.bytesAsSlice' avec validation préalable de taille : if (bytes.len < @sizeOf(T)) return error.BufferTooSmall;".to_string(),
                    });
                }
            }

            // 6. CVE-ZIG-BUFFER-OVERRUN-C-INTEROP (CWE-119 / CWE-120)
            let is_c_call = trimmed.contains("c.") || trimmed.contains("std.c.");
            if is_c_call {
                let unsafe_c_legacy = ["c.strcpy(", "c.sprintf(", "c.strcat(", "c.gets("];
                let has_legacy_fn = unsafe_c_legacy.iter().any(|f| trimmed.contains(f));
                let passes_raw_slice_ptr = trimmed.contains(".ptr") && !trimmed.contains("\"%s\"") && !content.contains("dupeZ") && !content.contains("[:0]");

                if has_legacy_fn || passes_raw_slice_ptr {
                    violations.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: line_no,
                        rule_id: "CVE-ZIG-BUFFER-OVERRUN-C-INTEROP".to_string(),
                        cve_id: "CWE-119 / C-INTEROP-BUFFER-OVERRUN".to_string(),
                        severity: "CRITICAL".to_string(),
                        message: "🚨 [CWE-119] BUFFER-OVERRUN-C-INTEROP : Passage d'un pointeur de tranche non terminé par un zéro sentinelle ([*:0]u8) à une fonction de l'ABI C, ou appel à une fonction C obsolète vulnérable aux dépassements de tampon.".to_string(),
                        transmitted_data: Some("c_abi_call_ptr".to_string()),
                        transmitted_type: Some("C-Pointer (Non-Sentinel Slice)".to_string()),
                        remediation: "Convertir la tranche en chaîne sentinelle terminée par null avec 'try allocator.dupeZ(u8, slice)' avant de passer le pointeur .ptr à l'ABI C.".to_string(),
                    });
                }
            }

            // 7. CVE-ZIG-UNPROTECTED-C-FORMAT-STRING (CWE-134)
            let is_c_printf = trimmed.contains("c.printf(") || trimmed.contains("std.c.printf(") || trimmed.contains("c.snprintf(") || trimmed.contains("c.fprintf(");
            if is_c_printf {
                // If c.printf(user_var) where argument does not start with a string literal format string
                if let Some(arg_start) = trimmed.find("printf(") {
                    let after = &trimmed[arg_start + 7..].trim_start();
                    if !after.starts_with('"') {
                        violations.push(LinterViolation {
                            file_path: file_path.to_string(),
                            line_number: line_no,
                            rule_id: "CVE-ZIG-UNPROTECTED-C-FORMAT-STRING".to_string(),
                            cve_id: "CWE-134 / UNPROTECTED-C-FORMAT-STRING".to_string(),
                            severity: "CRITICAL".to_string(),
                            message: "🚨 [CWE-134] UNPROTECTED-C-FORMAT-STRING : Passage d'une variable dynamique comme premier argument de format à une fonction de formatage C-ABI (risque d'injection de format string et RCE via %n).".to_string(),
                            transmitted_data: Some("format_string_arg".to_string()),
                            transmitted_type: Some("String (Dynamic Format Specifier)".to_string()),
                            remediation: "Utiliser impérativement une chaîne constante de formatage littérale telle que \"%s\" : c.printf(\"%s\", user_str.ptr);".to_string(),
                        });
                    }
                }
            }

            // 9. CVE-ZIG-COMMAND-INJECTION (CWE-78)
            let is_child_proc = trimmed.contains("std.process.Child.init(")
                || trimmed.contains("std.process.Child.run(")
                || trimmed.contains("ChildProcess.init(");
            if is_child_proc {
                let invokes_shell = trimmed.contains("\"/bin/sh\"")
                    || trimmed.contains("\"sh\"")
                    || trimmed.contains("\"bash\"")
                    || trimmed.contains("\"cmd.exe\"")
                    || trimmed.contains("\"cmd\"")
                    || trimmed.contains("\"powershell\"")
                    || trimmed.contains("\"-c\"")
                    || trimmed.contains("\"/c\"");
                if invokes_shell {
                    violations.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: line_no,
                        rule_id: "CVE-ZIG-COMMAND-INJECTION".to_string(),
                        cve_id: "CWE-78 / OS-COMMAND-INJECTION-CHILD".to_string(),
                        severity: "CRITICAL".to_string(),
                        message: "🚨 [CWE-78] COMMAND-INJECTION : Exécution d'un sous-processus via std.process.Child invoquant un interpréteur shell (-c / /c) avec des arguments dynamiques.".to_string(),
                        transmitted_data: Some("child_process_shell_argv".to_string()),
                        transmitted_type: Some("Slice ([]const []const u8 Shell Sink)".to_string()),
                        remediation: "Invoquer directement l'exécutable cible avec un tableau d'arguments discrets '&.{ \"program\", arg1 }' sans passer par '/bin/sh -c' ni 'cmd.exe /c'.".to_string(),
                    });
                }
            }

            // 10. CVE-ZIG-PATH-TRAVERSAL (CWE-22)
            let is_path_join = trimmed.contains("std.fs.path.join(");
            let is_direct_cwd_sink = [
                "std.fs.cwd().openFile(",
                "std.fs.cwd().readFileAlloc(",
                "std.fs.cwd().deleteFile(",
                "std.fs.cwd().deleteTree(",
            ]
            .iter()
            .any(|pat| {
                if let Some(pos) = trimmed.find(pat) {
                    let after = trimmed[pos + pat.len()..].trim_start();
                    !after.is_empty() && !after.starts_with('"')
                } else {
                    false
                }
            });
            let has_path_guard = content.contains("std.mem.indexOf(u8,")
                || content.contains("std.mem.indexOfScalar(")
                || content.contains("std.fs.path.basename(")
                || content.contains("realpath");
            let has_fs_sink = content.contains("openFile(")
                || content.contains("readFileAlloc(")
                || content.contains("deleteFile(")
                || content.contains("deleteTree(")
                || content.contains("createFile(");
            if ((is_path_join && has_fs_sink) || is_direct_cwd_sink) && !has_path_guard {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-ZIG-PATH-TRAVERSAL".to_string(),
                    cve_id: "CWE-22 / PATH-TRAVERSAL-UNCONFINED-FS".to_string(),
                    severity: "HIGH".to_string(),
                    message: "🚨 [CWE-22] PATH-TRAVERSAL : Construction de chemin via std.fs.path.join suivie d'une opération fichier sans filtrage des séquences '..' ni isolation par std.fs.path.basename.".to_string(),
                    transmitted_data: Some("joined_fs_path".to_string()),
                    transmitted_type: Some("FilePath (Unconfined Path Join)".to_string()),
                    remediation: "Extraire uniquement le nom de fichier via 'std.fs.path.basename(user_input)' ou rejeter toute entrée contenant '..' avec 'if (std.mem.indexOf(u8, input, \"..\") != null) return error.AccessDenied;'.".to_string(),
                });
            }

            // 11. CVE-ZIG-RUNTIME-SAFETY-DISABLED (CWE-676)
            if trimmed.contains("@setRuntimeSafety(false)") {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-ZIG-RUNTIME-SAFETY-DISABLED".to_string(),
                    cve_id: "CWE-676 / SET-RUNTIME-SAFETY-DISABLED-UB".to_string(),
                    severity: "HIGH".to_string(),
                    message: "🚨 [CWE-676] RUNTIME-SAFETY-DISABLED : Désactivation explicite des contrôles de sécurité mémoire et arithmétique via '@setRuntimeSafety(false)' (expose aux corruptions mémoire UB).".to_string(),
                    transmitted_data: Some("set_runtime_safety_false".to_string()),
                    transmitted_type: Some("CompilerBuiltin (Safety Check Bypass)".to_string()),
                    remediation: "Supprimer '@setRuntimeSafety(false)' et conserver les vérifications de bornes natives du compilateur Zig.".to_string(),
                });
            }

            // 13. CVE-ZIG-TLS-VERIFY-DISABLED (CWE-295)
            let is_tls_bypass = trimmed.contains("tls_skip_verify = true")
                || trimmed.contains(".ca_bundle = .none")
                || trimmed.contains("verify_certificate = false");
            if is_tls_bypass {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-ZIG-TLS-VERIFY-DISABLED".to_string(),
                    cve_id: "CWE-295 / TLS-CERTIFICATE-VERIFY-BYPASS".to_string(),
                    severity: "HIGH".to_string(),
                    message: "🚨 [CWE-295] TLS-VERIFY-DISABLED : Désactivation de la validation des certificats TLS/SSL dans la configuration cliente (vulnérable aux attaques Man-in-the-Middle).".to_string(),
                    transmitted_data: Some("tls_config_no_verify".to_string()),
                    transmitted_type: Some("TlsConfig (Certificate Validation Disabled)".to_string()),
                    remediation: "Activer la vérification du bundle d'autorités de certification système via 'ca_bundle.rescan(allocator)'.".to_string(),
                });
            }

            // 14. CVE-ZIG-WEAK-PRNG-CRYPTO (CWE-338)
            let is_weak_prng = trimmed.contains("DefaultPrng.init(") || trimmed.contains("Xoroshiro128.init(");
            if is_weak_prng {
                let lower_content = content.to_lowercase();
                let is_crypto_context = lower_content.contains("token")
                    || lower_content.contains("secret")
                    || lower_content.contains("key")
                    || lower_content.contains("nonce")
                    || lower_content.contains("salt")
                    || lower_content.contains("auth");
                if is_crypto_context {
                    violations.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: line_no,
                        rule_id: "CVE-ZIG-WEAK-PRNG-CRYPTO".to_string(),
                        cve_id: "CWE-338 / INSECURE-PRNG-DEFAULTPRNG".to_string(),
                        severity: "HIGH".to_string(),
                        message: "🚨 [CWE-338] WEAK-PRNG-CRYPTO : Utilisation de DefaultPrng / Xoroshiro128 (PRNG non cryptographique prédictible) dans un contexte de génération de clés, nonces ou jetons.".to_string(),
                        transmitted_data: Some("default_prng_state".to_string()),
                        transmitted_type: Some("Xoroshiro128 (Predictable PRNG)".to_string()),
                        remediation: "Utiliser le générateur cryptographique du système 'std.crypto.random.bytes(&buf)' ou 'std.crypto.random.int(u64)'.".to_string(),
                    });
                }
            }

            // 15. CVE-ZIG-SIMD-VECTOR-UNALIGNED-OOB (CWE-125)
            let is_simd_cast = trimmed.contains("@Vector(")
                && trimmed.contains("@ptrCast(")
                && trimmed.contains(".ptr")
                && !trimmed.contains("@alignCast(");
            if is_simd_cast {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-ZIG-SIMD-VECTOR-UNALIGNED-OOB".to_string(),
                    cve_id: "CWE-125 / SIMD-VECTOR-OUT-OF-BOUNDS".to_string(),
                    severity: "HIGH".to_string(),
                    message: "🚨 [CWE-125] SIMD-VECTOR-UNALIGNED-OOB : Chargement direct d'un pointeur de tranche dans un registre SIMD @Vector via @ptrCast sans @alignCast ni vérification de bornes.".to_string(),
                    transmitted_data: Some("simd_vector_ptr_cast".to_string()),
                    transmitted_type: Some("@Vector (Unaligned SIMD Pointer)".to_string()),
                    remediation: "Vérifier 'if (slice.len < N) return error.OutOfBounds;' et copier les éléments ou valider l'alignement SIMD avec '@alignCast'.".to_string(),
                });
            }
        }

        // Process any trailing function block
        if !fn_lines.is_empty() {
            Self::audit_function_block(file_path, &fn_lines, &mut violations);
        }

        violations
    }

    /// Audits function-scoped structural rules: Use-After-Free, Uninitialized Memory, and Allocator Leak.
    fn audit_function_block(
        file_path: &str,
        fn_lines: &[(usize, &str)],
        violations: &mut Vec<LinterViolation>,
    ) {
        let fn_text: String = fn_lines.iter().map(|(_, l)| *l).collect::<Vec<_>>().join("\n");

        // -------------------------------------------------------------
        // 1. CVE-ZIG-USE-AFTER-FREE (CWE-416)
        // -------------------------------------------------------------
        for (i, &(_line_no, line)) in fn_lines.iter().enumerate() {
            let trimmed = line.trim();
            // A non-deferred free or destroy
            let is_free_call = (trimmed.contains("allocator.free(") || trimmed.contains("allocator.destroy("))
                && !trimmed.starts_with("defer ")
                && !trimmed.contains(" defer ");

            if is_free_call {
                // Extract freed variable name
                let pattern = if trimmed.contains("allocator.free(") { "allocator.free(" } else { "allocator.destroy(" };
                if let Some(pos) = trimmed.find(pattern) {
                    let sub = &trimmed[pos + pattern.len()..];
                    if let Some(end_paren) = sub.find(')') {
                        let var_name = sub[..end_paren].trim();
                        if !var_name.is_empty() && var_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                            // Search remaining lines in this function for accesses
                            for &(use_line_no, use_line) in &fn_lines[i + 1..] {
                                let u_trim = use_line.trim();
                                if u_trim.starts_with("//") {
                                    continue;
                                }
                                // Stop if reassigned or reallocated
                                if u_trim.starts_with(&format!("{} = ", var_name)) || u_trim.contains(&format!("{} = try ", var_name)) {
                                    break;
                                }

                                let uses_var = u_trim.contains(&format!("{}[", var_name))
                                    || u_trim.contains(&format!("{}.*", var_name))
                                    || u_trim.contains(&format!("{}.", var_name))
                                    || u_trim.contains(&format!("return {};", var_name))
                                    || u_trim.contains(&format!("return {}[", var_name))
                                    || u_trim.contains(&format!("allocator.free({})", var_name));

                                if uses_var {
                                    violations.push(LinterViolation {
                                        file_path: file_path.to_string(),
                                        line_number: use_line_no,
                                        rule_id: "CVE-ZIG-USE-AFTER-FREE".to_string(),
                                        cve_id: "CWE-416 / USE-AFTER-FREE-ALLOCATOR".to_string(),
                                        severity: "CRITICAL".to_string(),
                                        message: format!(
                                            "🚨 [CWE-416] USE-AFTER-FREE : Accès à la tranche ou ressource mémoire '{}' après libération explicite via allocator.free() / destroy().",
                                            var_name
                                        ),
                                        transmitted_data: Some(var_name.to_string()),
                                        transmitted_type: Some("Heap-Pointer (Freed Memory Access)".to_string()),
                                        remediation: "Ne pas déréférencer ni indexer une ressource libérée. Déplacer la libération avec 'defer allocator.free(buffer)' en tête de fonction.".to_string(),
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // 5. CVE-ZIG-UNINITIALIZED-MEMORY (CWE-457)
        // -------------------------------------------------------------
        for (i, &(_line_no, line)) in fn_lines.iter().enumerate() {
            let trimmed = line.trim();
            // Detect: var x: [N]u8 = undefined;
            if trimmed.starts_with("var ") && trimmed.contains("= undefined") {
                let rest = &trimmed[4..];
                if let Some(colon) = rest.find(':') {
                    let var_name = rest[..colon].trim();
                    if !var_name.is_empty() && var_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        // Scan forward: check if read occurs BEFORE an initialization
                        for &(use_line_no, use_line) in &fn_lines[i + 1..] {
                            let u_trim = use_line.trim();
                            if u_trim.starts_with("//") {
                                continue;
                            }
                            // Initialization patterns -> safe, break loop
                            if u_trim.contains(&format!("@memset(&{}", var_name))
                                || u_trim.contains(&format!("@memset(& {}", var_name))
                                || u_trim.contains(&format!("@memcpy(&{}", var_name))
                                || u_trim.contains(&format!("readAll(&{}", var_name))
                                || u_trim.contains(&format!("read(&{}", var_name))
                                || u_trim.starts_with(&format!("{} = ", var_name))
                            {
                                break;
                            }

                            // Read / transmission patterns
                            if u_trim.contains(&format!("writeAll(&{}", var_name))
                                || u_trim.contains(&format!("write(&{}", var_name))
                                || u_trim.contains(&format!("send(&{}", var_name))
                                || u_trim.contains(&format!("return {};", var_name))
                                || u_trim.contains(&format!("return &{}", var_name))
                            {
                                violations.push(LinterViolation {
                                    file_path: file_path.to_string(),
                                    line_number: use_line_no,
                                    rule_id: "CVE-ZIG-UNINITIALIZED-MEMORY".to_string(),
                                    cve_id: "CWE-457 / UNINITIALIZED-MEMORY-ACCESS".to_string(),
                                    severity: "HIGH".to_string(),
                                    message: format!(
                                        "🚨 [CWE-457] UNINITIALIZED-MEMORY : Variable ou tampon '{}' initialisé avec '= undefined' et lu / transmis sans initialisation préalable.",
                                        var_name
                                    ),
                                    transmitted_data: Some(var_name.to_string()),
                                    transmitted_type: Some("Uninitialized Buffer (Stack Leak)".to_string()),
                                    remediation: "Initialiser explicitement le tampon avec '@memset(&buf, 0)' ou renseigner les champs avant toute lecture ou transmission.".to_string(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // 8. CVE-ZIG-RAW-ALLOCATOR-LEAK (CWE-401)
        // -------------------------------------------------------------
        for &(line_no, line) in fn_lines {
            let trimmed = line.trim();
            let is_allocation = (trimmed.contains("allocator.alloc(") || trimmed.contains("allocator.create("))
                && !trimmed.starts_with("//");

            if is_allocation {
                let has_defer_free = fn_text.contains("defer allocator.free")
                    || fn_text.contains("defer allocator.destroy")
                    || fn_text.contains("errdefer allocator.free")
                    || fn_text.contains("defer arena.deinit")
                    || fn_text.contains("defer list.deinit");

                // Check if the allocated variable is returned by the function
                let mut is_returned = false;
                if let Some(pos) = trimmed.find(" = ") {
                    let before = trimmed[..pos].trim();
                    let var_name = before.split_whitespace().last().unwrap_or("");
                    if !var_name.is_empty() && (fn_text.contains(&format!("return {}", var_name)) || fn_text.contains(&format!("return try {}", var_name))) {
                        is_returned = true;
                    }
                }

                if !has_defer_free && !is_returned {
                    violations.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: line_no,
                        rule_id: "CVE-ZIG-RAW-ALLOCATOR-LEAK".to_string(),
                        cve_id: "CWE-401 / RAW-ALLOCATOR-MEMORY-LEAK".to_string(),
                        severity: "HIGH".to_string(),
                        message: "🚨 [CWE-401] RAW-ALLOCATOR-LEAK : Allocation de mémoire dynamique sur le tas sans 'defer allocator.free()' correspondant et sans renvoi de la ressource allouée.".to_string(),
                        transmitted_data: Some("unmanaged_allocator_heap_block".to_string()),
                        transmitted_type: Some("Heap-Memory (Resource Leak)".to_string()),
                        remediation: "Ajouter 'defer allocator.free(slice)' immédiatement après l'allocation réussie ou utiliser un ArenaAllocator.".to_string(),
                    });
                }
            }
        }

        // -------------------------------------------------------------
        // 12. CVE-ZIG-STACK-ADDRESS-RETURN (CWE-562)
        // -------------------------------------------------------------
        for (i, &(_line_no, line)) in fn_lines.iter().enumerate() {
            let trimmed = line.trim();
            // Detect local stack buffer declaration: var buf: [N]u8 = ...
            if trimmed.starts_with("var ") && trimmed.contains('[') && trimmed.contains(']') {
                let rest = &trimmed[4..];
                if let Some(colon) = rest.find(':') {
                    let var_name = rest[..colon].trim();
                    if !var_name.is_empty() && var_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                        for &(ret_line_no, ret_line) in &fn_lines[i + 1..] {
                            let r_trim = ret_line.trim();
                            if r_trim.starts_with("//") {
                                continue;
                            }
                            let returns_stack_ptr = r_trim.contains(&format!("return &{};", var_name))
                                || r_trim.contains(&format!("return &{}[", var_name))
                                || r_trim.contains(&format!("return {}[0..", var_name));
                            if returns_stack_ptr {
                                violations.push(LinterViolation {
                                    file_path: file_path.to_string(),
                                    line_number: ret_line_no,
                                    rule_id: "CVE-ZIG-STACK-ADDRESS-RETURN".to_string(),
                                    cve_id: "CWE-562 / STACK-USE-AFTER-RETURN-DANGLING".to_string(),
                                    severity: "CRITICAL".to_string(),
                                    message: format!(
                                        "🚨 [CWE-562] STACK-ADDRESS-RETURN : Renvoi d'un pointeur ou d'une tranche vers le tampon de pile locale '{}' (Stack Use-After-Return immédiat).",
                                        var_name
                                    ),
                                    transmitted_data: Some(var_name.to_string()),
                                    transmitted_type: Some("Stack-Pointer (Dangling Return Slice)".to_string()),
                                    remediation: "Allouer le tampon sur le tas via 'try allocator.alloc(u8, N)' ou accepter un tampon de sortie fourni par l'appelant ('out_buf: []u8').".to_string(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}
