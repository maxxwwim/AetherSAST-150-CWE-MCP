use core_graph::dataflow::SanitizerRule;

/// Comprehensive Sanitizer Catalog for SAST taint tracking and neutralization.
/// Maps vulnerability CWE families to industry-standard and custom sanitization routines.
pub struct SanitizerCatalog;

impl SanitizerCatalog {
    /// Returns the complete list of standard built-in sanitizer rules across all CWEs.
    pub fn standard_rules() -> Vec<SanitizerRule> {
        SanitizerRule::default_catalog()
    }

    /// Returns sanitizer rules that apply to a specific CWE family (e.g. "CWE-89", "CWE-78").
    pub fn rules_for_cwe(cwe: &str) -> Vec<SanitizerRule> {
        SanitizerRule::default_catalog()
            .into_iter()
            .filter(|rule| {
                rule.neutralizes_all
                    || rule.target_cwes.iter().any(|c| {
                        c == "*"
                            || cwe == "*"
                            || c.eq_ignore_ascii_case(cwe)
                            || cwe.contains(c.as_str())
                            || c.contains(cwe)
                    })
            })
            .collect()
    }

    /// Evaluates if a given function name, method call, or expression is a recognized sanitizer for `cwe`.
    pub fn is_sanitizer(func_or_expr: &str, cwe: &str) -> bool {
        SanitizerRule::default_catalog()
            .iter()
            .any(|rule| rule.matches(func_or_expr, cwe))
    }

    /// Checks if a function name or expression is a sanitizer for ANY known vulnerability CWE.
    pub fn is_sanitizer_any_cwe(func_or_expr: &str) -> bool {
        SanitizerRule::default_catalog()
            .iter()
            .any(|rule| rule.matches(func_or_expr, "*"))
    }

    /// Finds the specific SanitizerRule that matches the given function/expression and CWE.
    pub fn find_matching_rule(func_or_expr: &str, cwe: &str) -> Option<SanitizerRule> {
        SanitizerRule::default_catalog()
            .into_iter()
            .find(|rule| rule.matches(func_or_expr, cwe))
    }

    /// Specific check for CWE-89 (SQL Injection) sanitizers:
    /// e.g. intval, clean_sql, prepare, PDO::quote, bind_param, mysqli_real_escape_string.
    pub fn is_sql_sanitizer(func_or_expr: &str) -> bool {
        Self::is_sanitizer(func_or_expr, "CWE-89")
    }

    /// Specific check for CWE-78 (Command Injection) sanitizers:
    /// e.g. escapeshellarg, escapeshellcmd, shlex.quote, shell-escape.
    pub fn is_command_sanitizer(func_or_expr: &str) -> bool {
        Self::is_sanitizer(func_or_expr, "CWE-78")
    }

    /// Specific check for CWE-79 (Cross-Site Scripting / XSS) sanitizers:
    /// e.g. htmlspecialchars, DOMPurify.sanitize, sanitizeHtml, escapeHtml, encodeURIComponent.
    pub fn is_xss_sanitizer(func_or_expr: &str) -> bool {
        Self::is_sanitizer(func_or_expr, "CWE-79")
    }

    /// Specific check for CWE-22 (Path Traversal) sanitizers:
    /// e.g. basename, sanitize_path, realpath, Path::canonicalize.
    pub fn is_path_sanitizer(func_or_expr: &str) -> bool {
        Self::is_sanitizer(func_or_expr, "CWE-22")
    }

    /// Scans a line of code or expression snippet to detect any recognized sanitizer calls for a given CWE.
    pub fn extract_sanitizers_from_snippet(snippet: &str, cwe: &str) -> Vec<String> {
        let rules = Self::rules_for_cwe(cwe);
        let mut detected = Vec::new();
        for rule in rules {
            if rule.matches(snippet, cwe) || snippet.contains(&rule.name) {
                if !detected.contains(&rule.name) {
                    detected.push(rule.name.clone());
                }
            }
        }
        detected
    }
}
