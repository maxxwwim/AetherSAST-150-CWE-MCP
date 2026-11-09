use crate::linter::{CveRuleDef, LinterViolation};

pub struct CSharpSecurityRules;

impl CSharpSecurityRules {
    /// Checks whether the file is a C# source file (.cs).
    pub fn is_csharp_file(file_path: &str) -> bool {
        let p = file_path.to_lowercase();
        p.ends_with(".cs")
    }

    /// Complete catalog of the 20 C# production CWE rules.
    pub fn definitions() -> Vec<CveRuleDef> {
        vec![
            // 1. CWE-502: Insecure Deserialization
            CveRuleDef {
                rule_id: "CVE-CS-INSECURE-DESERIALIZATION".to_string(),
                cve_id: "CWE-502 / INSECURE-DESERIALIZATION-DOTNET".to_string(),
                name: "Désérialisation Non Sécurisée d'Objets .NET (BinaryFormatter / TypeNameHandling RCE)".to_string(),
                category: "C# / Web Security".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Désérialisation d'un flux externe via BinaryFormatter, NetDataContractSerializer, LosFormatter, SoapFormatter, ou configuration de Newtonsoft.Json avec TypeNameHandling.Auto / All / Objects : instanciation arbitraire de gadgets .NET menant à l'exécution de code à distance (RCE).".to_string(),
                default_enabled: true,
            },
            // 2. CWE-89: SQL Injection
            CveRuleDef {
                rule_id: "CVE-CS-SQL-INJECTION".to_string(),
                cve_id: "CWE-89 / SQL-INJECTION-RAW-CONCAT".to_string(),
                name: "Injection SQL Directe via Interpolation ou Concaténation Dynamique".to_string(),
                category: "C# / Injection".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Construction dynamique de commandes SQL via interpolation ($) ou concaténation (+) transmise à SqlCommand, OleDbCommand, OdbcCommand, FromSqlRaw, ExecuteSqlRaw ou Dapper sans requête préparée ni paramètres nommés.".to_string(),
                default_enabled: true,
            },
            // 3. CWE-78: Command Injection
            CveRuleDef {
                rule_id: "CVE-CS-COMMAND-INJECTION".to_string(),
                cve_id: "CWE-78 / OS-COMMAND-INJECTION".to_string(),
                name: "Injection de Commande Système OS via Process.Start".to_string(),
                category: "C# / Injection".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Exécution de processus ou commandes système via Process.Start() avec des arguments concaténés dynamiquement depuis des entrées utilisateur ou via l'invocation d'interpréteurs de commande (cmd.exe /c, powershell.exe, bash).".to_string(),
                default_enabled: true,
            },
            // 4. CWE-22: Path Traversal
            CveRuleDef {
                rule_id: "CVE-CS-PATH-TRAVERSAL".to_string(),
                cve_id: "CWE-22 / PATH-TRAVERSAL-COMBINE".to_string(),
                name: "Traversée de Répertoire & Échappement de Racine via Path.Combine".to_string(),
                category: "C# / File Security".to_string(),
                severity: "HIGH".to_string(),
                description: "Combinaison de chemins via Path.Combine(baseFolder, fileName) sans vérification de confinement canonique (Path.GetFullPath). En .NET, si le second argument commence par un séparateur ('/' ou '\\'), Path.Combine ignore le dossier de base et renvoie la racine.".to_string(),
                default_enabled: true,
            },
            // 5. CWE-327 / CWE-328: Broken Cryptography
            CveRuleDef {
                rule_id: "CVE-CS-WEAK-CRYPTOGRAPHY".to_string(),
                cve_id: "CWE-327 / WEAK-CRYPTOGRAPHIC-PRIMITIVE".to_string(),
                name: "Utilisation d'Algorithmes Cryptographiques Obsolètes ou Cassés (MD5 / SHA1 / DES)".to_string(),
                category: "C# / Cryptography".to_string(),
                severity: "HIGH".to_string(),
                description: "Instanciation de fonctions de hachage vulnérables aux collisions (MD5, SHA1) ou de chiffrements symétriques faibles (DES, TripleDES, RC2, CipherMode.ECB) compromettant la confidentialité et l'intégrité.".to_string(),
                default_enabled: true,
            },
            // 6. CWE-79: Cross-Site Scripting via Raw HTML
            CveRuleDef {
                rule_id: "CVE-CS-XSS-RAW-HTML".to_string(),
                cve_id: "CWE-79 / XSS-RAW-HTML-INJECTION".to_string(),
                name: "Injection de Contenu HTML Non Échappé (Cross-Site Scripting / HtmlString / Html.Raw)".to_string(),
                category: "C# / Web Security".to_string(),
                severity: "HIGH".to_string(),
                description: "Affichage direct de contenu HTML non échappé dans des vues Razor ou Blazor via new HtmlString(userContent), @Html.Raw(userContent), (MarkupString)userContent ou Response.Write(userContent) désactivant l'encodage automatique.".to_string(),
                default_enabled: true,
            },
            // 7. CWE-611: XML External Entity (XXE)
            CveRuleDef {
                rule_id: "CVE-CS-XXE-INJECTION".to_string(),
                cve_id: "CWE-611 / XML-EXTERNAL-ENTITY-INJECTION".to_string(),
                name: "Injection d'Entités Externes XML (XXE / XmlResolver Non Sécurisé)".to_string(),
                category: "C# / XML Security".to_string(),
                severity: "HIGH".to_string(),
                description: "Analyse de documents XML via XmlDocument, XmlTextReader ou XPathDocument avec résolution des entités externes activée (XmlUrlResolver actif ou DtdProcessing.Parse sans XmlResolver = null).".to_string(),
                default_enabled: true,
            },
            // 8. CWE-330: Insecure PRNG
            CveRuleDef {
                rule_id: "CVE-CS-INSECURE-RANDOM".to_string(),
                cve_id: "CWE-330 / INSUFFICIENTLY-RANDOM-PRNG".to_string(),
                name: "Génération Pseudo-Aléatoire Non Cryptographique Prédictible (System.Random)".to_string(),
                category: "C# / Cryptography".to_string(),
                severity: "MEDIUM".to_string(),
                description: "Utilisation de System.Random (new Random()) pour la génération de secrets de sécurité : jetons d'authentification, codes de réinitialisation, clés de session ou nonces cryptographiques.".to_string(),
                default_enabled: true,
            },
            // 9. CWE-90: LDAP Injection
            CveRuleDef {
                rule_id: "CVE-CS-LDAP-INJECTION".to_string(),
                cve_id: "CWE-90 / LDAP-INJECTION-QUERY".to_string(),
                name: "Injection LDAP Directe via Concaténation de Filtre Active Directory".to_string(),
                category: "C# / Injection".to_string(),
                severity: "HIGH".to_string(),
                description: "Concaténation directe de chaînes d'entrée utilisateur dans le filtre de recherche DirectorySearcher.Filter sans échappement des caractères réservés LDAP (parenthèses, astérisque, backslash).".to_string(),
                default_enabled: true,
            },
            // 10. CWE-352: CSRF Disabled
            CveRuleDef {
                rule_id: "CVE-CS-CSRF-DISABLED".to_string(),
                cve_id: "CWE-352 / CSRF-PROTECTION-DISABLED".to_string(),
                name: "Désactivation Explicite de Protection Antiforgery (CSRF)".to_string(),
                category: "C# / Web Security".to_string(),
                severity: "MEDIUM".to_string(),
                description: "Désactivation explicite de la validation de jeton antiforgery sur un contrôleur ou une action ASP.NET Core modifiant l'état via l'attribut [IgnoreAntiforgeryToken].".to_string(),
                default_enabled: true,
            },
            // 11. CWE-918: Server-Side Request Forgery (SSRF) via HttpClient
            CveRuleDef {
                rule_id: "CVE-CS-SSRF-HTTPCLIENT".to_string(),
                cve_id: "CWE-918 / SSRF-OUTBOUND-HTTPCLIENT".to_string(),
                name: "Requête Réseau Sortante Non Validée (SSRF via HttpClient / WebClient)".to_string(),
                category: "C# / Web Security".to_string(),
                severity: "HIGH".to_string(),
                description: "Exécution d'une requête HTTP sortante via HttpClient.GetAsync, GetStringAsync, SendAsync ou WebClient.DownloadString avec une URL dynamique fournie par l'utilisateur sans liste blanche d'hôtes ni blocage des adresses IP privées/loopback (169.254.169.254).".to_string(),
                default_enabled: true,
            },
            // 12. CWE-295: TLS Server Certificate Validation Bypass
            CveRuleDef {
                rule_id: "CVE-CS-TLS-CERT-BYPASS".to_string(),
                cve_id: "CWE-295 / TLS-SERVER-CERT-VALIDATION-BYPASS".to_string(),
                name: "Contournement de Validation de Certificat TLS/SSL (ServerCertificateCustomValidationCallback)".to_string(),
                category: "C# / Cryptography".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Désactivation de la vérification des certificats TLS/SSL via HttpClientHandler.DangerousAcceptAnyServerCertificateValidator ou un callback ServerCertificateCustomValidationCallback renvoyant systématiquement true (exposition critique aux attaques MitM).".to_string(),
                default_enabled: true,
            },
            // 13. CWE-347: JWT Token Signature / Lifetime Validation Disabled
            CveRuleDef {
                rule_id: "CVE-CS-JWT-VALIDATION-BYPASS".to_string(),
                cve_id: "CWE-347 / JWT-TOKEN-VALIDATION-BYPASS".to_string(),
                name: "Désactivation de Validation Cryptographique JWT (TokenValidationParameters)".to_string(),
                category: "C# / Web Security".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Configuration de TokenValidationParameters avec ValidateIssuerSigningKey = false, RequireSignedTokens = false ou ValidateLifetime = false, permettant à un attaquant de forger des jetons JWT arbitraires sans clé secrète.".to_string(),
                default_enabled: true,
            },
            // 14. CWE-601: Unvalidated Open Redirect
            CveRuleDef {
                rule_id: "CVE-CS-OPEN-REDIRECT".to_string(),
                cve_id: "CWE-601 / UNVALIDATED-OPEN-REDIRECT".to_string(),
                name: "Redirection HTTP Ouverte Non Validée (Redirect vs LocalRedirect)".to_string(),
                category: "C# / Web Security".to_string(),
                severity: "HIGH".to_string(),
                description: "Redirection vers une URL contrôlée par le client via Redirect(returnUrl) ou RedirectPermanent(url) sans validation Url.IsLocalUrl(returnUrl) ni utilisation de LocalRedirect(), facilitant le phishing et le vol de jetons OAuth.".to_string(),
                default_enabled: true,
            },
            // 15. CWE-915: Mass Assignment / Over-Posting in ASP.NET Core
            CveRuleDef {
                rule_id: "CVE-CS-MASS-ASSIGNMENT".to_string(),
                cve_id: "CWE-915 / ASPNET-OVERPOSTING-MASS-ASSIGNMENT".to_string(),
                name: "Affectation de Masse Non Filtrée (Mass Assignment / TryUpdateModelAsync)".to_string(),
                category: "C# / Web Security".to_string(),
                severity: "HIGH".to_string(),
                description: "Mise à jour directe d'une entité de domaine via TryUpdateModelAsync(model) sans expression de restriction des propriétés autorisées ni attribut [Bind], permettant l'élévation de privilèges par injection de champs sensibles (IsAdmin, Role, Balance).".to_string(),
                default_enabled: true,
            },
            // 16. CWE-1333: Regular Expression Denial of Service (ReDoS)
            CveRuleDef {
                rule_id: "CVE-CS-REDOS-UNBOUNDED-REGEX".to_string(),
                cve_id: "CWE-1333 / REGEX-MISSING-TIMEOUT-REDOS".to_string(),
                name: "Expression Régulière Sans Timeout ni NonBacktracking (Déni de Service ReDoS)".to_string(),
                category: "C# / Web Security".to_string(),
                severity: "HIGH".to_string(),
                description: "Évaluation d'une expression régulière dynamique via new Regex(pattern) ou Regex.IsMatch(input, pattern) sans définir de TimeSpan matchTimeout ni RegexOptions.NonBacktracking, permettant de bloquer les threads Kestrel.".to_string(),
                default_enabled: true,
            },
            // 17. CWE-798: Hardcoded Credentials & JWT Signing Keys
            CveRuleDef {
                rule_id: "CVE-CS-HARDCODED-CREDENTIALS".to_string(),
                cve_id: "CWE-798 / HARDCODED-SECRET-KEY-CONNSTRING".to_string(),
                name: "Clé Cryptographique JWT ou Mot de Passe de Connexion Codé en Dur".to_string(),
                category: "C# / Cryptography".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Clé secrète HMAC codée en dur dans SymmetricSecurityKey(Encoding.UTF8.GetBytes(\"...\")) ou chaîne de connexion contenant un mot de passe littéral (Password=...;) directement dans le code source C#.".to_string(),
                default_enabled: true,
            },
            // 18. CWE-787: Unbounded stackalloc Buffer Overflow / Crash DoS
            CveRuleDef {
                rule_id: "CVE-CS-UNSAFE-STACKALLOC-OVERFLOW".to_string(),
                cve_id: "CWE-787 / UNBOUNDED-STACKALLOC-CRASH-DOS".to_string(),
                name: "Allocation sur Pile Non Bornée (stackalloc Dynamique / StackOverflow DoS)".to_string(),
                category: "C# / Memory Safety".to_string(),
                severity: "HIGH".to_string(),
                description: "Allocation sur la pile via stackalloc byte[dynamicLength] avec une taille dynamique non bornée : en .NET, un dépassement de pile lève une StackOverflowException non interceptable qui tue instantanément le processus serveur.".to_string(),
                default_enabled: true,
            },
            // 19. CWE-470: Unsafe Reflection & Dynamic Type Instantiation
            CveRuleDef {
                rule_id: "CVE-CS-UNSAFE-REFLECTION-INVOKE".to_string(),
                cve_id: "CWE-470 / UNSAFE-TYPE-GETTYPE-ACTIVATOR-RCE".to_string(),
                name: "Réflexion Non Sécurisée & Instanciation Dynamique de Type (Type.GetType / Assembly.LoadFrom)".to_string(),
                category: "C# / Injection".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Résolution et instanciation dynamique de classes via Type.GetType(userType) + Activator.CreateInstance ou chargement d'assembly externe via Assembly.LoadFrom(userPath) permettant l'exécution de code arbitraire.".to_string(),
                default_enabled: true,
            },
            // 20. CWE-209: Sensitive Exception StackTrace Exposure
            CveRuleDef {
                rule_id: "CVE-CS-SENSITIVE-ERROR-EXPOSURE".to_string(),
                cve_id: "CWE-209 / EXCEPTION-STACKTRACE-EXPOSURE".to_string(),
                name: "Divulgation de Trace de Pile et Détails Internes d'Exception dans la Réponse HTTP".to_string(),
                category: "C# / Web Security".to_string(),
                severity: "MEDIUM".to_string(),
                description: "Renvoi direct de ex.ToString() ou ex.StackTrace dans une réponse HTTP (BadRequest, StatusCode, Ok), exposant la structure interne du code, les chemins serveur et les requêtes SQL aux attaquants.".to_string(),
                default_enabled: true,
            },
        ]
    }

    /// Convenience audit function taking only file_path and content.
    pub fn audit(file_path: &str, content: &str) -> Vec<LinterViolation> {
        Self::audit_file(file_path, content, false, false)
    }

    /// Full static audit of a C# source file.
    pub fn audit_file(
        file_path: &str,
        content: &str,
        is_test_file: bool,
        is_interface_or_types: bool,
    ) -> Vec<LinterViolation> {
        let mut violations = Vec::new();

        // Isolation: execute STRICTLY on C# files
        if !Self::is_csharp_file(file_path) || is_test_file || is_interface_or_types {
            return violations;
        }

        let lines: Vec<&str> = content.lines().collect();

        // Check global file patterns
        let has_path_guard = content.contains(".StartsWith(")
            || content.contains("Path.GetFileName(")
            || content.contains("StringComparison.OrdinalIgnoreCase");

        let has_xml_defense = content.contains("DtdProcessing.Prohibit")
            || content.contains("XmlResolver = null");

        let has_ldap_sanitizer = content.contains(".Replace(\"(\"")
            || content.contains("LdapFilterEncode");

        let has_xss_encoder = content.contains("HtmlEncoder.Default.Encode")
            || content.contains("HttpUtility.HtmlEncode")
            || content.contains("WebUtility.HtmlEncode")
            || content.contains("Sanitize(");

        for (idx, &line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }

            // -------------------------------------------------------------
            // 1. CVE-CS-INSECURE-DESERIALIZATION (CWE-502)
            // -------------------------------------------------------------
            let is_binary_formatter = trimmed.contains("BinaryFormatter")
                || trimmed.contains("NetDataContractSerializer")
                || trimmed.contains("LosFormatter")
                || trimmed.contains("SoapFormatter");
            let is_type_name_handling = trimmed.contains("TypeNameHandling.Auto")
                || trimmed.contains("TypeNameHandling.All")
                || trimmed.contains("TypeNameHandling.Objects");

            if is_binary_formatter || is_type_name_handling {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-INSECURE-DESERIALIZATION".to_string(),
                    cve_id: "CWE-502 / INSECURE-DESERIALIZATION-DOTNET".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "🚨 [CWE-502] INSECURE-DESERIALIZATION : Désérialisation via BinaryFormatter ou TypeNameHandling polymorphique. Permet l'instanciation de gadget chains .NET et l'exécution de code à distance (RCE).".to_string(),
                    transmitted_data: Some("untrusted_stream_formatter".to_string()),
                    transmitted_type: Some("BinaryFormatter / TypeNameHandling (Gadget RCE)".to_string()),
                    remediation: "Éviter BinaryFormatter (obsolète et dangereux). Utiliser System.Text.Json.JsonSerializer ou configurer TypeNameHandling = TypeNameHandling.None.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 2. CVE-CS-SQL-INJECTION (CWE-89)
            // -------------------------------------------------------------
            let has_sql_verb = trimmed.contains("SELECT ")
                || trimmed.contains("INSERT INTO ")
                || trimmed.contains("UPDATE ")
                || trimmed.contains("DELETE FROM ");
            let has_sql_call = trimmed.contains("SqlCommand(")
                || trimmed.contains("FromSqlRaw(")
                || trimmed.contains("ExecuteSqlRaw(")
                || trimmed.contains("ExecuteSqlRawAsync(")
                || trimmed.contains("OleDbCommand(")
                || trimmed.contains("OdbcCommand(")
                || trimmed.contains(".Query(");

            let is_interpolated_sql = trimmed.contains("$\"SELECT")
                || trimmed.contains("$\"DELETE")
                || trimmed.contains("$\"UPDATE")
                || trimmed.contains("$\"INSERT")
                || (has_sql_verb && (trimmed.contains(" + ") || trimmed.contains("$\"")));

            let is_safe_ef_interpolated = trimmed.contains("FromSqlInterpolated");
            let is_param_sql = trimmed.contains("@") && trimmed.contains("Parameters.AddWithValue");

            if (is_interpolated_sql || (has_sql_call && (trimmed.contains("$\"") || trimmed.contains(" + ")))) && !is_safe_ef_interpolated && !is_param_sql {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-SQL-INJECTION".to_string(),
                    cve_id: "CWE-89 / SQL-INJECTION-RAW-CONCAT".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "🚨 [CWE-89] SQL-INJECTION : Requête SQL exécutée via interpolation brute ou concaténation de chaînes dynamiques. Permet l'injection SQL et la compromission intégrale de la base de données.".to_string(),
                    transmitted_data: Some("dynamic_sql_query".to_string()),
                    transmitted_type: Some("String (Unsanitized Dynamic SQL)".to_string()),
                    remediation: "Utiliser des requêtes SQL paramétrées avec 'cmd.Parameters.AddWithValue(\"@param\", value)' ou la méthode 'FromSqlInterpolated' de Entity Framework Core.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 3. CVE-CS-COMMAND-INJECTION (CWE-78)
            // -------------------------------------------------------------
            let is_process_start = trimmed.contains("Process.Start(");
            let is_shell_runner = trimmed.contains("\"cmd.exe\"")
                || trimmed.contains("\"cmd\"")
                || trimmed.contains("\"powershell.exe\"")
                || trimmed.contains("\"powershell\"")
                || trimmed.contains("\"bash\"");

            let has_dynamic_arg = trimmed.contains(" + ") || (trimmed.contains("$\"") && trimmed.contains('{'));
            let is_process_arg_concat = trimmed.contains("Arguments = ") && has_dynamic_arg;

            if (is_process_start && (is_shell_runner || has_dynamic_arg)) || is_process_arg_concat {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-COMMAND-INJECTION".to_string(),
                    cve_id: "CWE-78 / OS-COMMAND-INJECTION".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "🚨 [CWE-78] COMMAND-INJECTION : Exécution de commandes système OS via Process.Start avec des arguments dynamiquement concaténés ou invocation d'interpréteur shell.".to_string(),
                    transmitted_data: Some("process_command_args".to_string()),
                    transmitted_type: Some("ProcessStartInfo (Shell Injection Sink)".to_string()),
                    remediation: "Utiliser 'ProcessStartInfo.ArgumentList.Add()' pour ajouter chaque argument séparément sans passer par un interpréteur shell.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 4. CWE-22: Path Traversal
            // -------------------------------------------------------------
            if trimmed.contains("Path.Combine(") && !has_path_guard {
                // Check if result is used in file operations
                let has_file_op = content.contains("File.ReadAllText")
                    || content.contains("File.Open")
                    || content.contains("File.ReadAllBytes")
                    || content.contains("File.WriteAllText")
                    || content.contains("FileStream");

                if has_file_op {
                    violations.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: line_no,
                        rule_id: "CVE-CS-PATH-TRAVERSAL".to_string(),
                        cve_id: "CWE-22 / PATH-TRAVERSAL-COMBINE".to_string(),
                        severity: "HIGH".to_string(),
                        message: "🚨 [CWE-22] PATH-TRAVERSAL : Concaténation de chemin via Path.Combine sans vérification canonique (StartsWith). Si l'entrée utilisateur commence par un slash ou une racine, Path.Combine ignore le dossier de base.".to_string(),
                        transmitted_data: Some("path_combine_result".to_string()),
                        transmitted_type: Some("FilePath (Unbounded Path Traversal)".to_string()),
                        remediation: "Vérifier le chemin canonique résolu avec : if (!Path.GetFullPath(fullPath).StartsWith(canonicalBase, StringComparison.OrdinalIgnoreCase)) throw ... ou utiliser Path.GetFileName().".to_string(),
                    });
                }
            }

            // -------------------------------------------------------------
            // 5. CWE-327 / CWE-328: Broken Cryptography
            // -------------------------------------------------------------
            let is_weak_hash = trimmed.contains("MD5.Create()")
                || trimmed.contains("MD5CryptoServiceProvider")
                || trimmed.contains("MD5.HashData(")
                || trimmed.contains("SHA1.Create()")
                || trimmed.contains("SHA1CryptoServiceProvider")
                || trimmed.contains("SHA1Managed")
                || trimmed.contains("SHA1.HashData(");
            let is_weak_cipher = trimmed.contains("DES.Create()")
                || trimmed.contains("DESCryptoServiceProvider")
                || trimmed.contains("TripleDESCryptoServiceProvider")
                || trimmed.contains("RC2CryptoServiceProvider")
                || trimmed.contains("CipherMode.ECB");

            if is_weak_hash || is_weak_cipher {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-WEAK-CRYPTOGRAPHY".to_string(),
                    cve_id: "CWE-327 / WEAK-CRYPTOGRAPHIC-PRIMITIVE".to_string(),
                    severity: "HIGH".to_string(),
                    message: "🚨 [CWE-327] WEAK-CRYPTOGRAPHY : Utilisation d'un algorithme cryptographique cassé ou vulnérable aux collisions (MD5, SHA1, DES, RC2, CipherMode.ECB).".to_string(),
                    transmitted_data: Some("weak_crypto_primitive".to_string()),
                    transmitted_type: Some("CryptoAlgorithm (Deprecated Primitive)".to_string()),
                    remediation: "Migrer vers SHA-256 (SHA256.Create()) ou SHA-512 pour le hachage et vers AES-256 (Aes.Create()) avec CipherMode.CBC ou GCM pour le chiffrement symétrique.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 6. CWE-79: Cross-Site Scripting via Raw HTML
            // -------------------------------------------------------------
            let is_raw_html = trimmed.contains("new HtmlString(")
                || trimmed.contains("@Html.Raw(")
                || trimmed.contains("(MarkupString)")
                || trimmed.contains("Response.Write(");
            let is_encoded = trimmed.contains("HtmlEncoder.Default.Encode")
                || trimmed.contains("HttpUtility.HtmlEncode")
                || trimmed.contains("WebUtility.HtmlEncode")
                || trimmed.contains("Sanitize(");

            if is_raw_html && !is_encoded && !has_xss_encoder {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-XSS-RAW-HTML".to_string(),
                    cve_id: "CWE-79 / XSS-RAW-HTML-INJECTION".to_string(),
                    severity: "HIGH".to_string(),
                    message: "🚨 [CWE-79] XSS-RAW-HTML : Rendu de contenu HTML brut non encodé via HtmlString / @Html.Raw / MarkupString désactivant l'échappement automatique de Razor (vulnérabilité XSS).".to_string(),
                    transmitted_data: Some("raw_html_output".to_string()),
                    transmitted_type: Some("HtmlString (Unsanitized HTML Payload)".to_string()),
                    remediation: "Encoder les données utilisateur dynamiques avec 'HtmlEncoder.Default.Encode()' ou assainir avec un filtre HTML avant de créer un HtmlString.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 7. CWE-611: XML External Entity (XXE)
            // -------------------------------------------------------------
            let is_xxe_sink = trimmed.contains("new XmlUrlResolver()")
                || trimmed.contains("XmlResolver = new XmlUrlResolver()");
            let is_dtd_parse_risky = trimmed.contains("DtdProcessing.Parse") && !has_xml_defense;

            if is_xxe_sink || is_dtd_parse_risky {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-XXE-INJECTION".to_string(),
                    cve_id: "CWE-611 / XML-EXTERNAL-ENTITY-INJECTION".to_string(),
                    severity: "HIGH".to_string(),
                    message: "🚨 [CWE-611] XXE-INJECTION : Analyseur XML configuré avec résolution des entités externes DTD activée (XmlUrlResolver actif). Permet la divulgation de fichiers locaux et les attaques SSRF.".to_string(),
                    transmitted_data: Some("xml_resolver_setting".to_string()),
                    transmitted_type: Some("XmlReaderSettings (External Entity Resolver Enabled)".to_string()),
                    remediation: "Désactiver le traitement DTD et les entités externes : 'settings.DtdProcessing = DtdProcessing.Prohibit;' et 'settings.XmlResolver = null;'.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 8. CWE-330: Insecure PRNG
            // -------------------------------------------------------------
            let is_system_random = trimmed.contains("new Random()") || trimmed.contains("Random.Shared");
            if is_system_random {
                let context_lower = content.to_lowercase();
                let is_security_sensitive = context_lower.contains("token")
                    || context_lower.contains("auth")
                    || context_lower.contains("secret")
                    || context_lower.contains("password")
                    || context_lower.contains("nonce")
                    || context_lower.contains("code")
                    || context_lower.contains("salt")
                    || context_lower.contains("key");

                if is_security_sensitive {
                    violations.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: line_no,
                        rule_id: "CVE-CS-INSECURE-RANDOM".to_string(),
                        cve_id: "CWE-330 / INSUFFICIENTLY-RANDOM-PRNG".to_string(),
                        severity: "MEDIUM".to_string(),
                        message: "🚨 [CWE-330] INSECURE-RANDOM : Utilisation de System.Random (PRNG non cryptographique prédictible) pour générer des jetons d'authentification ou des secrets de sécurité.".to_string(),
                        transmitted_data: Some("predictable_random_number".to_string()),
                        transmitted_type: Some("System.Random (Insecure Pseudo-Random Value)".to_string()),
                        remediation: "Utiliser 'System.Security.Cryptography.RandomNumberGenerator.GetInt32()' ou 'GetBytes()' pour générer des valeurs aléatoires sécurisées.".to_string(),
                    });
                }
            }

            // -------------------------------------------------------------
            // 9. CWE-90: LDAP Injection
            // -------------------------------------------------------------
            let is_ldap_filter = (trimmed.contains(".Filter = ") || trimmed.contains("DirectorySearcher("))
                && (trimmed.contains("objectClass") || trimmed.contains("sAMAccountName") || trimmed.contains("cn="));
            let has_concat = trimmed.contains(" + ") || (trimmed.contains("$\"") && trimmed.contains('{'));

            if is_ldap_filter && has_concat && !has_ldap_sanitizer {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-LDAP-INJECTION".to_string(),
                    cve_id: "CWE-90 / LDAP-INJECTION-QUERY".to_string(),
                    severity: "HIGH".to_string(),
                    message: "🚨 [CWE-90] LDAP-INJECTION : Concaténation directe d'entrées externes dans un filtre de recherche DirectorySearcher Active Directory sans échappement de métacaractères LDAP.".to_string(),
                    transmitted_data: Some("ldap_filter_query".to_string()),
                    transmitted_type: Some("DirectorySearcher.Filter (Unsanitized LDAP Filter)".to_string()),
                    remediation: "Échapper les caractères réservés LDAP ('(', ')', '*', '\\') ou utiliser 'Encoder.LdapFilterEncode()' avant d'injecter la variable dans le filtre.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 10. CWE-352: CSRF Disabled
            // -------------------------------------------------------------
            if trimmed.contains("[IgnoreAntiforgeryToken]") {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-CSRF-DISABLED".to_string(),
                    cve_id: "CWE-352 / CSRF-PROTECTION-DISABLED".to_string(),
                    severity: "MEDIUM".to_string(),
                    message: "🚨 [CWE-352] CSRF-DISABLED : Protection antiforgery explicitement désactivée ([IgnoreAntiforgeryToken]) sur un endpoint d'action d'état modifiant les données (vulnérabilité CSRF).".to_string(),
                    transmitted_data: Some("csrf_disabled_action".to_string()),
                    transmitted_type: Some("ActionMethodAttribute (Antiforgery Token Bypass)".to_string()),
                    remediation: "Supprimer l'attribut [IgnoreAntiforgeryToken] et imposer [ValidateAntiForgeryToken] sur toutes les actions POST/PUT/DELETE modifiant l'état.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 11. CWE-918: SSRF via HttpClient / WebClient
            // -------------------------------------------------------------
            let http_methods = [".GetAsync(", ".GetStringAsync(", ".GetByteArrayAsync(", ".DownloadString(", ".DownloadData("];
            if let Some(m) = http_methods.iter().find(|&&m| trimmed.contains(m)) {
                if let Some(pos) = trimmed.find(m) {
                    let arg = trimmed[pos + m.len()..].trim_start();
                    let is_literal_url = arg.starts_with('"') || arg.starts_with("$\"https://") || arg.starts_with("new Uri(\"http");
                    let has_ssrf_guard = content.contains("Uri.TryCreate")
                        || content.contains("AllowedHosts")
                        || content.contains("IsLoopback")
                        || content.contains(".Host ==");
                    if !is_literal_url && !arg.starts_with(')') && !has_ssrf_guard {
                        violations.push(LinterViolation {
                            file_path: file_path.to_string(),
                            line_number: line_no,
                            rule_id: "CVE-CS-SSRF-HTTPCLIENT".to_string(),
                            cve_id: "CWE-918 / SSRF-OUTBOUND-HTTPCLIENT".to_string(),
                            severity: "HIGH".to_string(),
                            message: "🚨 [CWE-918] SSRF-HTTPCLIENT : Requête HTTP sortante exécutée vers une URL dynamique sans validation d'hôte ni filtrage des adresses internes (169.254.169.254 / loopback).".to_string(),
                            transmitted_data: Some("outbound_http_url".to_string()),
                            transmitted_type: Some("Uri / String (Unvalidated Outbound Request)".to_string()),
                            remediation: "Valider l'URI avec 'Uri.TryCreate', vérifier que 'uri.Scheme == Uri.UriSchemeHttps', contrôler 'uri.Host' sur une liste blanche et rejeter les IP privées.".to_string(),
                        });
                    }
                }
            }

            // -------------------------------------------------------------
            // 12. CWE-295: TLS Certificate Validation Bypass
            // -------------------------------------------------------------
            let is_tls_bypass = trimmed.contains("DangerousAcceptAnyServerCertificateValidator")
                || (trimmed.contains("ServerCertificateCustomValidationCallback") && trimmed.contains("=> true"))
                || (trimmed.contains("ServerCertificateValidationCallback") && trimmed.contains("=> true"));
            if is_tls_bypass {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-TLS-CERT-BYPASS".to_string(),
                    cve_id: "CWE-295 / TLS-SERVER-CERT-VALIDATION-BYPASS".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "🚨 [CWE-295] TLS-CERT-BYPASS : Contournement explicite de la validation des certificats TLS/SSL (acceptation aveugle de tout certificat serveur, risque critique de Man-in-the-Middle).".to_string(),
                    transmitted_data: Some("tls_cert_validator_callback".to_string()),
                    transmitted_type: Some("HttpClientHandler (TLS Validation Disabled)".to_string()),
                    remediation: "Supprimer DangerousAcceptAnyServerCertificateValidator et vérifier que 'sslPolicyErrors == SslPolicyErrors.None'.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 13. CWE-347: JWT Token Validation Bypass
            // -------------------------------------------------------------
            let is_jwt_bypass = trimmed.contains("ValidateIssuerSigningKey = false")
                || trimmed.contains("RequireSignedTokens = false")
                || trimmed.contains("ValidateLifetime = false")
                || trimmed.contains("RequireExpirationTime = false");
            if is_jwt_bypass {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-JWT-VALIDATION-BYPASS".to_string(),
                    cve_id: "CWE-347 / JWT-TOKEN-VALIDATION-BYPASS".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "🚨 [CWE-347] JWT-VALIDATION-BYPASS : Désactivation de la vérification de signature ou d'expiration dans TokenValidationParameters (permet la forge de jetons JWT arbitraires).".to_string(),
                    transmitted_data: Some("jwt_token_validation_params".to_string()),
                    transmitted_type: Some("TokenValidationParameters (Signature Bypass)".to_string()),
                    remediation: "Imposer 'ValidateIssuerSigningKey = true', 'RequireSignedTokens = true' et 'ValidateLifetime = true' dans TokenValidationParameters.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 14. CWE-601: Unvalidated Open Redirect
            // -------------------------------------------------------------
            let is_redirect_call = trimmed.contains("return Redirect(") || trimmed.contains("return RedirectPermanent(");
            if is_redirect_call && !content.contains("Url.IsLocalUrl(") && !content.contains("LocalRedirect(") {
                let after_redir = if let Some(p) = trimmed.find("Redirect(") {
                    trimmed[p + 9..].trim_start()
                } else if let Some(p) = trimmed.find("RedirectPermanent(") {
                    trimmed[p + 18..].trim_start()
                } else {
                    ""
                };
                if !after_redir.is_empty() && !after_redir.starts_with('"') {
                    violations.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: line_no,
                        rule_id: "CVE-CS-OPEN-REDIRECT".to_string(),
                        cve_id: "CWE-601 / UNVALIDATED-OPEN-REDIRECT".to_string(),
                        severity: "HIGH".to_string(),
                        message: "🚨 [CWE-601] OPEN-REDIRECT : Redirection HTTP vers une URL contrôlée par l'utilisateur sans vérification Url.IsLocalUrl() ni utilisation de LocalRedirect().".to_string(),
                        transmitted_data: Some("redirect_target_url".to_string()),
                        transmitted_type: Some("IActionResult (Unvalidated Redirect URL)".to_string()),
                        remediation: "Remplacer 'Redirect(returnUrl)' par 'LocalRedirect(returnUrl)' ou vérifier 'if (!Url.IsLocalUrl(returnUrl)) return RedirectToAction(\"Index\");'.".to_string(),
                    });
                }
            }

            // -------------------------------------------------------------
            // 15. CWE-915: Mass Assignment / Over-Posting
            // -------------------------------------------------------------
            if trimmed.contains("TryUpdateModelAsync(") && !trimmed.contains("=>") && !content.contains("[Bind(") {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-MASS-ASSIGNMENT".to_string(),
                    cve_id: "CWE-915 / ASPNET-OVERPOSTING-MASS-ASSIGNMENT".to_string(),
                    severity: "HIGH".to_string(),
                    message: "🚨 [CWE-915] MASS-ASSIGNMENT : Appel à TryUpdateModelAsync sans filtre d'inclusion de propriétés (permet la modification de champs privilégiés tels que Role ou IsAdmin).".to_string(),
                    transmitted_data: Some("unfiltered_model_binding".to_string()),
                    transmitted_type: Some("ModelBinding (Unrestricted Entity Update)".to_string()),
                    remediation: "Utiliser un ViewModel/DTO dédié ou spécifier explicitement les champs autorisés : 'await TryUpdateModelAsync(user, \"\", u => u.Name, u => u.Email)'.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 16. CWE-1333: ReDoS Unbounded Regular Expression
            // -------------------------------------------------------------
            let is_regex_eval = trimmed.contains("new Regex(") || trimmed.contains("Regex.IsMatch(") || trimmed.contains("Regex.Match(");
            if is_regex_eval
                && !trimmed.contains("TimeSpan.")
                && !trimmed.contains("NonBacktracking")
                && !content.contains("RegexOptions.NonBacktracking")
            {
                let has_timeout_arg = trimmed.matches(',').count() >= 2;
                if !has_timeout_arg {
                    violations.push(LinterViolation {
                        file_path: file_path.to_string(),
                        line_number: line_no,
                        rule_id: "CVE-CS-REDOS-UNBOUNDED-REGEX".to_string(),
                        cve_id: "CWE-1333 / REGEX-MISSING-TIMEOUT-REDOS".to_string(),
                        severity: "HIGH".to_string(),
                        message: "🚨 [CWE-1333] REDOS-UNBOUNDED-REGEX : Évaluation d'expression régulière sans TimeSpan matchTimeout ni RegexOptions.NonBacktracking (risque de blocage CPU par ReDoS).".to_string(),
                        transmitted_data: Some("unbounded_regex_pattern".to_string()),
                        transmitted_type: Some("System.Text.RegularExpressions.Regex (Missing Timeout)".to_string()),
                        remediation: "Ajouter un délai d'expiration explicite 'TimeSpan.FromMilliseconds(250)' ou utiliser 'RegexOptions.NonBacktracking' (.NET 7+).".to_string(),
                    });
                }
            }

            // -------------------------------------------------------------
            // 17. CWE-798: Hardcoded Credentials & JWT Keys
            // -------------------------------------------------------------
            let is_hardcoded_jwt_key = (trimmed.contains("SymmetricSecurityKey(") && trimmed.contains("GetBytes(\""))
                || ((trimmed.contains("const string ") || trimmed.contains("readonly string "))
                    && (trimmed.contains("JwtSecret")
                        || trimmed.contains("SecretKey")
                        || trimmed.contains("ClientSecret")
                        || trimmed.contains("ApiSecret"))
                    && trimmed.contains("= \""));
            let is_hardcoded_conn_pwd = (trimmed.contains("Server=") || trimmed.contains("Data Source="))
                && (trimmed.contains("Password=") || trimmed.contains("Pwd="))
                && !trimmed.contains("{");
            if is_hardcoded_jwt_key || is_hardcoded_conn_pwd {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-HARDCODED-CREDENTIALS".to_string(),
                    cve_id: "CWE-798 / HARDCODED-SECRET-KEY-CONNSTRING".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "🚨 [CWE-798] HARDCODED-CREDENTIALS : Clé secrète cryptographique JWT ou mot de passe de connexion codé en dur dans le code source C#.".to_string(),
                    transmitted_data: Some("hardcoded_secret_literal".to_string()),
                    transmitted_type: Some("SymmetricSecurityKey / ConnectionString (Hardcoded Secret)".to_string()),
                    remediation: "Charger les secrets depuis un coffre-fort sécurisé (Azure KeyVault, Variables d'environnement, IConfiguration) hors du dépôt Git.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 18. CWE-787: Unbounded stackalloc Overflow
            // -------------------------------------------------------------
            if let Some(sa_pos) = trimmed.find("stackalloc ") {
                let after_sa = &trimmed[sa_pos + 11..];
                if let (Some(open_b), Some(close_b)) = (after_sa.find('['), after_sa.find(']')) {
                    if close_b > open_b {
                        let size_expr = after_sa[open_b + 1..close_b].trim();
                        let is_const_num = !size_expr.is_empty() && size_expr.chars().all(|c| c.is_ascii_digit() || c == '_');
                        if !is_const_num && !content.contains("Math.Min(") && !content.contains("if (") {
                            violations.push(LinterViolation {
                                file_path: file_path.to_string(),
                                line_number: line_no,
                                rule_id: "CVE-CS-UNSAFE-STACKALLOC-OVERFLOW".to_string(),
                               cve_id: "CWE-787 / UNBOUNDED-STACKALLOC-CRASH-DOS".to_string(),
                                severity: "HIGH".to_string(),
                                message: "🚨 [CWE-787] UNSAFE-STACKALLOC-OVERFLOW : Allocation sur la pile via 'stackalloc' avec une taille dynamique non bornée (provoque un crash immédiat par StackOverflowException).".to_string(),
                                transmitted_data: Some(size_expr.to_string()),
                                transmitted_type: Some("Span<T> (Unbounded Stack Allocation)".to_string()),
                                remediation: "Borner strictement la taille allouée sur la pile (ex: <= 1024 octets) et utiliser 'ArrayPool<byte>.Shared.Rent()' au-delà.".to_string(),
                            });
                        }
                    }
                }
            }

            // -------------------------------------------------------------
            // 19. CWE-470: Unsafe Reflection & Dynamic Type Instantiation
            // -------------------------------------------------------------
            let is_unsafe_reflection = (trimmed.contains("Type.GetType(") && !trimmed.contains("Type.GetType(\""))
                || (trimmed.contains("Assembly.LoadFrom(") && !trimmed.contains("Assembly.LoadFrom(\""))
                || trimmed.contains("CSharpScript.EvaluateAsync(");
            if is_unsafe_reflection {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-UNSAFE-REFLECTION-INVOKE".to_string(),
                    cve_id: "CWE-470 / UNSAFE-TYPE-GETTYPE-ACTIVATOR-RCE".to_string(),
                    severity: "CRITICAL".to_string(),
                    message: "🚨 [CWE-470] UNSAFE-REFLECTION-INVOKE : Résolution dynamique de type (Type.GetType) ou chargement d'assembly externe depuis une entrée non fiable permettant l'exécution de code arbitraire.".to_string(),
                    transmitted_data: Some("dynamic_reflection_type".to_string()),
                    transmitted_type: Some("System.Type / Assembly (Unvalidated Reflection)".to_string()),
                    remediation: "Valider le nom de type sur une liste blanche fermée d'identifiants autorisés ou utiliser un dictionnaire de fabriques typées.".to_string(),
                });
            }

            // -------------------------------------------------------------
            // 20. CWE-209: Sensitive Exception StackTrace Exposure
            // -------------------------------------------------------------
            let is_error_leak = trimmed.contains("BadRequest(ex.ToString())")
                || trimmed.contains("BadRequest(ex.StackTrace)")
                || trimmed.contains("StatusCode(500, ex.ToString())")
                || trimmed.contains("StatusCode(500, ex.StackTrace)")
                || trimmed.contains("Problem(ex.StackTrace)");
            if is_error_leak {
                violations.push(LinterViolation {
                    file_path: file_path.to_string(),
                    line_number: line_no,
                    rule_id: "CVE-CS-SENSITIVE-ERROR-EXPOSURE".to_string(),
                    cve_id: "CWE-209 / EXCEPTION-STACKTRACE-EXPOSURE".to_string(),
                    severity: "MEDIUM".to_string(),
                    message: "🚨 [CWE-209] SENSITIVE-ERROR-EXPOSURE : Divulgation directe de la trace de pile d'exception (ex.StackTrace / ex.ToString()) dans la réponse HTTP envoyée au client.".to_string(),
                    transmitted_data: Some("exception_stacktrace".to_string()),
                    transmitted_type: Some("Exception (Sensitive Diagnostic Leak)".to_string()),
                    remediation: "Journaliser l'exception côté serveur via 'ILogger.LogError(ex, ...)' et retourner un message générique 'Problem(\"Internal server error\")' au client.".to_string(),
                });
            }
        }

        violations
    }
}
