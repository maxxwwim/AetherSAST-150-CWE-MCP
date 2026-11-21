use crate::lexer::AuditContext;
use crate::linter::{CveRuleDef, LinterViolation};
use core_graph::dataflow::{SanitizerRule, TaintRuleSet, TaintSinkRule, TaintSourceRule};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

fn default_true() -> bool {
    true
}

fn default_category() -> String {
    "Plugin / Security".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum MatchMode {
    #[default]
    LineByLine,
    WholeFile,
}


/// Condition de fenêtrage contextuel : la règle se déclenche uniquement si aucun des `patterns`
/// n'est présent dans les `lines` lignes précédant strictement la ligne fautive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PrecededWindowCondition {
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub lines: usize,
}

/// Matchers pré-compilés par règle (100% `Send + Sync`, zéro `Mutex`).
#[derive(Debug, Clone, Default)]
pub struct CompiledRuleMatchers {
    pub trigger_regexes: Vec<Regex>,
    pub window_regexes: Vec<Regex>,
    pub in_path_regexes: Vec<Regex>,
    pub not_in_path_regexes: Vec<Regex>,
    pub lower_extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleConditions {
    /// Mots ou sous-chaînes qui DOIVENT obligatoirement être présents
    #[serde(default)]
    pub must_contain: Vec<String>,
    /// Mots ou motifs qui, s'ils sont présents, neutralisent l'alerte (atténuation valide)
    #[serde(default)]
    pub must_not_contain: Vec<String>,
    /// Expressions régulières déclenchant la violation
    #[serde(default)]
    pub regex_patterns: Vec<String>,
    /// Jetons ou sous-chaînes interdites déclenchant la violation
    #[serde(default)]
    pub forbidden_tokens: Vec<String>,
    /// Si true, évalue sur le code brut (littéraux inclus). Si false, masque commentaires & chaînes
    #[serde(default)]
    pub check_literals: bool,
    /// Fenêtrage contextuel : exige qu'aucun motif garde n'apparaisse dans les N lignes précédentes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_preceded_within_lines: Option<PrecededWindowCondition>,
    /// Globs de chemins de fichiers requis (ex: `["src/api/**"]`)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub in_path_matching: Vec<String>,
    /// Globs de chemins de fichiers exclus (ex: `["**/generated/**"]`, prioritaire sur `in_path_matching`)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_in_path_matching: Vec<String>,
    /// Portée syntaxique AST requise (`"outside_test"`, `"async_fn"`, `"sync_fn"`, `"fn"`, `"test"`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ast_scope: Option<String>,
    /// Cache interne pré-compilé (ignoré par Serde)
    #[serde(skip)]
    pub compiled: OnceLock<CompiledRuleMatchers>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleTestCase {
    pub name: String,
    pub code: String,
    pub file_name: String,
    pub should_trigger: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginRule {
    pub id: String,
    pub cwe_id: String,
    pub name: String,
    #[serde(default = "default_category")]
    pub category: String,
    pub severity: String, // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "WARNING"
    pub description: String,
    pub remediation: String,
    #[serde(default)]
    pub file_extensions: Vec<String>,
    #[serde(default)]
    pub match_mode: MatchMode,
    #[serde(default)]
    pub conditions: RuleConditions,
    #[serde(default)]
    pub test_cases: Vec<RuleTestCase>,
}

fn glob_to_regex(glob: &str) -> Option<Regex> {
    let g = glob.replace('\\', "/");
    let g = g.trim().trim_start_matches("./").trim_start_matches('/');
    if g.is_empty() {
        return None;
    }
    let mut out = String::from("(?i)^");
    let bytes = g.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 2 < bytes.len() && &bytes[i..i + 3] == b"**/" {
            out.push_str("(?:.*/)?");
            i += 3;
        } else if i + 2 == bytes.len() && &bytes[i..i + 2] == b"**" {
            out.push_str(".*");
            i += 2;
        } else if bytes[i] == b'*' {
            out.push_str("[^/]*");
            i += 1;
        } else if bytes[i] == b'?' {
            out.push_str("[^/]");
            i += 1;
        } else {
            let ch = g[i..].chars().next().unwrap();
            if ".+^$()[]{}|\\".contains(ch) {
                out.push('\\');
            }
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out.push('$');
    Regex::new(&out).ok()
}

impl PluginRule {
    /// Retourne (et initialise si nécessaire de manière lock-free) les expressions régulières précompilées.
    pub fn compiled(&self) -> &CompiledRuleMatchers {
        self.conditions.compiled.get_or_init(|| {
            let trigger_regexes = self
                .conditions
                .regex_patterns
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect();

            let window_regexes = self
                .conditions
                .not_preceded_within_lines
                .as_ref()
                .map(|w| {
                    w.patterns
                        .iter()
                        .filter_map(|p| Regex::new(p).ok())
                        .collect()
                })
                .unwrap_or_default();

            let in_path_regexes = self
                .conditions
                .in_path_matching
                .iter()
                .filter_map(|g| glob_to_regex(g))
                .collect();

            let not_in_path_regexes = self
                .conditions
                .not_in_path_matching
                .iter()
                .filter_map(|g| glob_to_regex(g))
                .collect();

            let lower_extensions = self
                .file_extensions
                .iter()
                .map(|e| e.to_ascii_lowercase())
                .collect();

            CompiledRuleMatchers {
                trigger_regexes,
                window_regexes,
                in_path_regexes,
                not_in_path_regexes,
                lower_extensions,
            }
        })
    }

    /// Force la pré-compilation immédiate au chargement du manifeste.
    pub fn precompile(&self) {
        let _ = self.compiled();
    }

    /// Valide la syntaxe de toutes les expressions régulières (triggers et fenêtre contextuelle).
    pub fn validate_regexes(&self) -> Result<(), String> {
        for pat in &self.conditions.regex_patterns {
            Regex::new(pat).map_err(|e| format!("Invalid regex pattern '{pat}': {e}"))?;
        }
        if let Some(ref win) = self.conditions.not_preceded_within_lines {
            for pat in &win.patterns {
                Regex::new(pat).map_err(|e| format!("Invalid window regex '{pat}': {e}"))?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_sources: Vec<TaintSourceRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_sinks: Vec<TaintSinkRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sanitizers: Vec<SanitizerRule>,
    #[serde(default)]
    pub rules: Vec<PluginRule>,
    #[serde(skip)]
    pub folder_alias: Option<String>,
}

impl Default for PluginManifest {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: "1.0.0".to_string(),
            author: None,
            description: None,
            enabled: true,
            profile: None,
            tags: Vec::new(),
            taint_sources: Vec::new(),
            taint_sinks: Vec::new(),
            sanitizers: Vec::new(),
            rules: Vec::new(),
            folder_alias: None,
        }
    }
}

impl PluginManifest {
    pub fn precompile_all(&self) {
        for r in &self.rules {
            r.precompile();
        }
    }

    pub fn matches_selector(&self, selector: &str) -> bool {
        let sel = selector.trim();
        if let Some(prof) = sel
            .strip_prefix("profile:")
            .or_else(|| sel.strip_prefix("PROFILE:"))
        {
            let prof = prof.trim();
            self.profile
                .as_deref()
                .is_some_and(|p| p.eq_ignore_ascii_case(prof))
                || self.tags.iter().any(|t| t.eq_ignore_ascii_case(prof))
        } else {
            self.name.eq_ignore_ascii_case(sel)
                || self
                    .folder_alias
                    .as_deref()
                    .is_some_and(|f| f.eq_ignore_ascii_case(sel))
        }
    }

    pub fn matches_any_selector(&self, selectors: &[String]) -> bool {
        selectors.iter().any(|s| self.matches_selector(s))
    }
}

/// Sélection de plugins issue du flag CLI `--plugins`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PluginSelection {
    /// Comportement par défaut (sans `--plugins`) : règles natives + tous les plugins `.aether/plugins/` actifs.
    #[default]
    Default,
    /// Détection automatique de la stack (`--plugins auto`) + plugins `.aether/plugins/` actifs.
    Auto,
    /// Toutes les règles natives et tous les packs de plugins (`--plugins all`).
    All,
    /// Sélection explicite de packs ou de profils (`--plugins pack-a,profile:strict`).
    Select(Vec<String>),
}

pub const BUILTIN_PACK_NAMES: &[&str] = &[
    "builtin-rust",
    "rust",
    "rust-l1",
    "builtin-web3",
    "web3",
    "solidity",
    "defi",
    "builtin-python",
    "python",
    "py",
    "builtin-javascript",
    "javascript",
    "js",
    "typescript",
    "ts",
    "builtin-php",
    "php",
    "builtin-zig",
    "zig",
    "builtin-csharp",
    "csharp",
    "cs",
    "dotnet",
    "builtin-cpp",
    "cpp",
    "c",
    "builtin-deep",
    "deep",
    "builtin-epic",
    "epic",
    "novel",
    "architecture",
    "arch",
    "core",
];

pub fn is_builtin_selector(selector: &str) -> bool {
    let sel = selector.trim();
    if let Some(prof) = sel
        .strip_prefix("profile:")
        .or_else(|| sel.strip_prefix("PROFILE:"))
    {
        let prof = prof.trim();
        BUILTIN_PACK_NAMES
            .iter()
            .any(|b| b.eq_ignore_ascii_case(prof))
    } else {
        BUILTIN_PACK_NAMES
            .iter()
            .any(|b| b.eq_ignore_ascii_case(sel))
    }
}

pub fn rule_matches_builtin_selector(rule_id: &str, category: &str, file_path: &str, selector: &str) -> bool {
    let raw = selector
        .trim()
        .strip_prefix("profile:")
        .or_else(|| selector.trim().strip_prefix("PROFILE:"))
        .unwrap_or(selector.trim())
        .trim()
        .to_ascii_lowercase();
    let up_id = rule_id.to_ascii_uppercase();
    let low_cat = category.to_ascii_lowercase();
    let low_fp = file_path.to_ascii_lowercase();

    match raw.as_str() {
        "builtin-rust" | "rust" | "rust-l1" => {
            up_id.contains("RUST")
                || up_id.starts_with("CVE-L1-")
                || low_cat.contains("rust")
                || low_fp.ends_with(".rs")
        }
        "builtin-web3" | "web3" | "solidity" | "defi" => {
            up_id.contains("WEB3")
                || up_id.contains("DEFI")
                || up_id.contains("EVC")
                || up_id.contains("ERC4337")
                || up_id.contains("EVM")
                || up_id.contains("ZK")
                || low_cat.contains("web3")
                || low_fp.ends_with(".sol")
        }
        "builtin-python" | "python" | "py" => {
            up_id.contains("-PY-") || low_fp.ends_with(".py")
        }
        "builtin-javascript" | "javascript" | "js" | "typescript" | "ts" => {
            up_id.contains("-JS-")
                || up_id.contains("CLIENT")
                || low_cat.contains("front-end")
                || low_fp.ends_with(".js")
                || low_fp.ends_with(".ts")
                || low_fp.ends_with(".tsx")
                || low_fp.ends_with(".jsx")
        }
        "builtin-php" | "php" => {
            up_id.contains("-PHP-") || low_cat.contains("php") || low_fp.ends_with(".php")
        }
        "builtin-zig" | "zig" => {
            up_id.contains("-ZIG-") || low_cat.contains("zig") || low_fp.ends_with(".zig")
        }
        "builtin-csharp" | "csharp" | "cs" | "dotnet" => {
            up_id.contains("-CS-") || low_cat.contains("c#") || low_fp.ends_with(".cs")
        }
        "builtin-cpp" | "cpp" | "c" => {
            up_id.contains("-CPP-")
                || low_fp.ends_with(".cpp")
                || low_fp.ends_with(".c")
                || low_fp.ends_with(".cc")
                || low_fp.ends_with(".h")
                || low_fp.ends_with(".hpp")
        }
        "builtin-deep" | "deep" => {
            up_id.contains("-INJ-") || up_id.contains("-VM-") || up_id.contains("-WASM-")
        }
        "builtin-epic" | "epic" | "novel" => up_id.starts_with("AETHER-"),
        "architecture" | "arch" | "core" => {
            up_id.starts_with("RULE_") || up_id.starts_with("SAST_") || up_id == "BLAKE3_TAMPERED"
        }
        _ => false,
    }
}

impl PluginSelection {
    /// Parse une spécification CLI `--plugins <SPEC>`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err("Invalid --plugins specification: cannot be empty".to_string());
        }
        if trimmed.eq_ignore_ascii_case("auto") {
            return Ok(PluginSelection::Auto);
        }
        if trimmed.eq_ignore_ascii_case("all") {
            return Ok(PluginSelection::All);
        }
        if trimmed.eq_ignore_ascii_case("default") {
            return Ok(PluginSelection::Default);
        }

        let mut items: Vec<String> = Vec::new();
        for part in trimmed.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            if let Some(prof) = p
                .strip_prefix("profile:")
                .or_else(|| p.strip_prefix("PROFILE:"))
            {
                if prof.trim().is_empty() {
                    return Err("Invalid --plugins specification: empty profile name".to_string());
                }
            }
            if !items.iter().any(|existing| existing.eq_ignore_ascii_case(p)) {
                items.push(p.to_string());
            }
        }

        if items.is_empty() {
            return Err("Invalid --plugins specification: no valid plugin pack or profile specified".to_string());
        }

        Ok(PluginSelection::Select(items))
    }

    pub fn has_any_builtin_selected(&self) -> bool {
        match self {
            PluginSelection::Default | PluginSelection::Auto | PluginSelection::All => true,
            PluginSelection::Select(items) => items.iter().any(|s| is_builtin_selector(s)),
        }
    }

    pub fn canonical_key(&self) -> String {
        match self {
            PluginSelection::Default => "default".to_string(),
            PluginSelection::Auto => "auto".to_string(),
            PluginSelection::All => "all".to_string(),
            PluginSelection::Select(items) => {
                let mut sorted: Vec<String> = items.iter().map(|s| s.to_ascii_lowercase()).collect();
                sorted.sort();
                format!("select:{}", sorted.join(","))
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PluginTestReport {
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub failures: Vec<String>,
}

#[derive(Clone, Copy, Default)]
struct LineAstScope {
    in_test: bool,
    in_fn: bool,
    in_async_fn: bool,
}

fn compute_line_ast_scopes(raw_lines: &[&str], lower_path: &str) -> Vec<LineAstScope> {
    let is_test_file = lower_path.contains("/tests/")
        || lower_path.contains("/test/")
        || lower_path.starts_with("tests/")
        || lower_path.starts_with("test/")
        || lower_path.ends_with("_test.rs")
        || lower_path.ends_with("_tests.rs")
        || lower_path.contains(".spec.")
        || lower_path.contains(".test.");

    let is_py = lower_path.ends_with(".py");
    let mut out = vec![
        LineAstScope {
            in_test: is_test_file,
            in_fn: false,
            in_async_fn: false,
        };
        raw_lines.len()
    ];

    let mut brace_depth: i32 = 0;
    let mut cfg_test_pending = false;
    let mut cfg_test_active = false;
    let mut cfg_test_base_depth: i32 = 0;
    let mut cfg_test_opened = false;

    let mut pending_test_fn = false;
    // (base_depth, is_async, is_test_fn, opened_brace)
    let mut active_brace_fn: Option<(i32, bool, bool, bool)> = None;
    // (indent, is_async, is_test_fn)
    let mut active_py_fn: Option<(usize, bool, bool)> = None;

    for (idx, &raw_line) in raw_lines.iter().enumerate() {
        let trimmed = raw_line.trim();
        let is_comment = trimmed.starts_with("//")
            || (trimmed.starts_with('#') && !trimmed.starts_with("#["))
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*');

        if is_py {
            if !trimmed.is_empty() && !is_comment {
                let indent = raw_line.len() - raw_line.trim_start().len();
                if let Some((fn_indent, _, _)) = active_py_fn {
                    if indent <= fn_indent && !trimmed.starts_with('@') {
                        active_py_fn = None;
                    }
                }
                if trimmed.starts_with("async def ") || trimmed.starts_with("def ") {
                    let is_async = trimmed.starts_with("async def ");
                    let fn_name = trimmed
                        .trim_start_matches("async ")
                        .trim_start_matches("def ")
                        .trim();
                    let is_test = is_test_file || fn_name.starts_with("test_");
                    active_py_fn = Some((indent, is_async, is_test));
                }
            }
            if let Some((_, is_async, is_test)) = active_py_fn {
                out[idx].in_fn = true;
                out[idx].in_async_fn = is_async;
                out[idx].in_test |= is_test;
            }
            continue;
        }

        if !is_comment {
            if trimmed == "#[cfg(test)]"
                || trimmed.starts_with("#[cfg(all(test")
                || trimmed == "mod tests {"
                || trimmed == "mod test {"
            {
                cfg_test_pending = true;
                cfg_test_base_depth = brace_depth;
                cfg_test_active = true;
                cfg_test_opened = false;
            }
            if trimmed == "#[test]"
                || trimmed.starts_with("#[tokio::test")
                || trimmed.starts_with("#[rstest")
            {
                pending_test_fn = true;
            }

            if active_brace_fn.is_none() {
                let is_async_decl = trimmed.contains("async fn ")
                    || trimmed.contains("async function")
                    || (trimmed.contains("async ") && trimmed.contains("=>"));
                let is_sync_decl = !is_async_decl
                    && (trimmed.starts_with("fn ")
                        || trimmed.contains(" fn ")
                        || trimmed.starts_with("function ")
                        || trimmed.contains(" function "));
                if is_async_decl || is_sync_decl {
                    active_brace_fn = Some((
                        brace_depth,
                        is_async_decl,
                        pending_test_fn || cfg_test_active || is_test_file,
                        false,
                    ));
                    pending_test_fn = false;
                }
            }
        }

        let open_braces = if is_comment {
            0
        } else {
            trimmed.bytes().filter(|&b| b == b'{').count() as i32
        };
        let close_braces = if is_comment {
            0
        } else {
            trimmed.bytes().filter(|&b| b == b'}').count() as i32
        };

        if cfg_test_active && open_braces > 0 {
            cfg_test_opened = true;
        }
        if let Some((_, _, _, ref mut opened)) = active_brace_fn {
            if open_braces > 0 {
                *opened = true;
            }
        }

        if cfg_test_active {
            out[idx].in_test = true;
        }
        if let Some((_, is_async, is_test_fn, _)) = active_brace_fn {
            out[idx].in_fn = true;
            out[idx].in_async_fn = is_async;
            out[idx].in_test |= is_test_fn;
        }

        brace_depth += open_braces - close_braces;

        if let Some((base_depth, _, _, opened)) = active_brace_fn {
            if (opened && brace_depth <= base_depth)
                || (!opened && !is_comment && trimmed.ends_with(';'))
            {
                active_brace_fn = None;
            }
        }
        if (cfg_test_active && cfg_test_opened && brace_depth <= cfg_test_base_depth)
            || (cfg_test_pending && !cfg_test_opened && open_braces == 0 && trimmed.ends_with(';'))
        {
            cfg_test_active = false;
            cfg_test_pending = false;
        }
    }

    out
}

fn scope_matches(required_scope: &str, scope: LineAstScope) -> bool {
    match required_scope.trim().to_ascii_lowercase().as_str() {
        "outside_test" | "non_test" | "prod" | "production" => !scope.in_test,
        "test" | "in_test" => scope.in_test,
        "async_fn" | "async" | "async_function" => scope.in_async_fn && !scope.in_test,
        "sync_fn" | "sync" | "sync_function" => scope.in_fn && !scope.in_async_fn && !scope.in_test,
        "fn" | "function" => scope.in_fn && !scope.in_test,
        _ => true,
    }
}

#[derive(Debug, Clone, Default)]
pub struct PluginEngine {
    pub plugins: Vec<PluginManifest>,
    pub selection: PluginSelection,
}

impl PluginEngine {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            selection: PluginSelection::Default,
        }
    }

    /// Charge un plugin depuis une chaîne YAML ou JSON et pré-compile toutes ses règles.
    pub fn load_from_str(&mut self, content: &str) -> Result<&PluginManifest, String> {
        let manifest: PluginManifest = match serde_yaml::from_str(content) {
            Ok(m) => m,
            Err(yaml_err) => match serde_yaml::from_str::<serde_json::Value>(content)
                .ok()
                .and_then(|v| serde_json::from_value::<PluginManifest>(v).ok())
            {
                Some(m) => m,
                None => serde_json::from_str(content).map_err(|json_err| {
                    format!("YAML parse error: {yaml_err}; JSON parse error: {json_err}")
                })?,
            },
        };
        manifest.precompile_all();
        self.plugins.push(manifest);
        Ok(self.plugins.last().unwrap())
    }

    /// Charge tous les fichiers plugins (*.yaml, *.yml, *.json) depuis un dossier (triés de façon déterministe).
    pub fn load_from_directory<P: AsRef<Path>>(&mut self, dir_path: P) -> Result<usize, String> {
        let p = dir_path.as_ref();
        if !p.exists() {
            return Err(format!("Plugin directory does not exist: {}", p.display()));
        }

        let mut loaded_count = 0;
        self.scan_and_load_dir(p, &mut loaded_count)?;
        Ok(loaded_count)
    }

    fn scan_and_load_dir(&mut self, dir: &Path, count: &mut usize) -> Result<(), String> {
        let rd = fs::read_dir(dir).map_err(|e| format!("Cannot read dir {}: {e}", dir.display()))?;
        let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();

        for path in entries {
            if path.is_dir() {
                if path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case("visuals"))
                {
                    continue;
                }
                self.scan_and_load_dir(&path, count)?;
            } else if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                if path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case("visual-plugin"))
                {
                    continue;
                }
                let ext_lower = ext.to_ascii_lowercase();
                if ext_lower == "yaml" || ext_lower == "yml" || ext_lower == "json" {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let folder_alias = path
                            .parent()
                            .and_then(|p| p.file_name())
                            .map(|s| s.to_string_lossy().to_string());
                        if self.load_from_str(&content).is_ok() {
                            if let Some(last) = self.plugins.last_mut() {
                                last.folder_alias = folder_alias;
                                if last.enabled {
                                    *count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Charge les plugins du dossier `.aether/plugins` (s'il existe) et applique/valide la sélection `--plugins`.
    pub fn load_with_selection(
        &mut self,
        plugins_dir: Option<&Path>,
        selection: &PluginSelection,
    ) -> Result<usize, String> {
        self.selection = selection.clone();
        if let Some(dir) = plugins_dir {
            if dir.is_dir() {
                let _ = self.load_from_directory(dir);
            }
        }

        if let PluginSelection::Select(ref selectors) = self.selection {
            for sel in selectors {
                let matched_local = self
                    .plugins
                    .iter()
                    .any(|p| p.enabled && p.matches_selector(sel));
                let matched_builtin = is_builtin_selector(sel);
                if !matched_local && !matched_builtin {
                    return Err(format!("Unknown plugin pack or profile: '{}'", sel));
                }
            }

            for plugin in &mut self.plugins {
                if plugin.enabled {
                    plugin.enabled = plugin.matches_any_selector(selectors);
                }
            }
        }

        Ok(self.plugins.iter().filter(|p| p.enabled).count())
    }

    /// Retourne le nombre total de règles actives dans les plugins chargés.
    pub fn total_rules_count(&self) -> usize {
        self.plugins
            .iter()
            .filter(|p| p.enabled)
            .map(|p| p.rules.len())
            .sum()
    }

    /// Collecte toutes les règles déclaratives de taint (`taint_sources`, `taint_sinks`, `sanitizers`) des plugins actifs.
    pub fn collect_taint_rules(&self) -> TaintRuleSet {
        let mut set = TaintRuleSet::new();
        for plugin in &self.plugins {
            if !plugin.enabled {
                continue;
            }
            for src in &plugin.taint_sources {
                set.add_source(src.clone());
            }
            for sink in &plugin.taint_sinks {
                set.add_sink(sink.clone());
            }
            for san in &plugin.sanitizers {
                set.add_sanitizer(san.clone());
            }
        }
        set
    }

    /// Calcule une empreinte BLAKE3 déterministe de la sélection `--plugins` et de tous les plugins actifs.
    pub fn config_digest(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"aether-plugin-engine-v2:");
        hasher.update(self.selection.canonical_key().as_bytes());
        hasher.update(b"|");
        for plugin in &self.plugins {
            if !plugin.enabled {
                continue;
            }
            if let Ok(json_bytes) = serde_json::to_vec(plugin) {
                hasher.update(&json_bytes);
                hasher.update(b";");
            }
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Exporte la liste des définitions de règles au format natif AetherScope (`CveRuleDef`),
    /// incluant à la fois `rules` et `taint_sinks`.
    pub fn get_cve_rule_defs(&self) -> Vec<CveRuleDef> {
        let mut defs = Vec::new();
        let mut seen = HashSet::new();
        for plugin in &self.plugins {
            if !plugin.enabled {
                continue;
            }
            for rule in &plugin.rules {
                if seen.insert(rule.id.clone()) {
                    defs.push(CveRuleDef {
                        rule_id: rule.id.clone(),
                        cve_id: rule.cwe_id.clone(),
                        name: format!("[{}] {}", plugin.name, rule.name),
                        category: rule.category.clone(),
                        severity: rule.severity.clone(),
                        description: rule.description.clone(),
                        default_enabled: true,
                    });
                }
            }
            for sink in &plugin.taint_sinks {
                let id = if sink.rule_id.is_empty() {
                    sink.name.clone()
                } else {
                    sink.rule_id.clone()
                };
                if !id.is_empty() && seen.insert(id.clone()) {
                    defs.push(CveRuleDef {
                        rule_id: id,
                        cve_id: sink.cwe.clone(),
                        name: format!("[{}] {}", plugin.name, sink.name),
                        category: "Plugin / Taint Dataflow".to_string(),
                        severity: sink.severity.clone(),
                        description: sink.description.clone(),
                        default_enabled: true,
                    });
                }
            }
        }
        defs
    }

    /// Audite un fichier avec les plugins actifs (signature `&self` immuable, 100% lock-free).
    pub fn audit_file(&self, file_path: &str, content: &str) -> Vec<LinterViolation> {
        let ctx = AuditContext::new(file_path, content);
        self.audit_file_with_context(&ctx)
    }

    /// Audite un fichier en partageant un [`AuditContext`] pré-calculé.
    pub fn audit_file_with_context(&self, ctx: &AuditContext<'_>) -> Vec<LinterViolation> {
        let mut violations = Vec::new();
        if self.plugins.is_empty() {
            return violations;
        }

        let norm_path = ctx.file_path.replace('\\', "/");
        let norm_rel = norm_path.trim_start_matches("./").trim_start_matches('/');

        let raw_lines_cell: OnceLock<Vec<&str>> = OnceLock::new();
        let masked_lines_cell: OnceLock<Vec<&str>> = OnceLock::new();
        let ast_scopes_cell: OnceLock<Vec<LineAstScope>> = OnceLock::new();

        let mut seen_rule_lines: HashSet<(String, usize)> = HashSet::new();

        for plugin in &self.plugins {
            if !plugin.enabled {
                continue;
            }

            for rule in &plugin.rules {
                let compiled = rule.compiled();

                // 1. Filtrage par extension
                if !compiled.lower_extensions.is_empty() {
                    let extension_matches = compiled
                        .lower_extensions
                        .iter()
                        .any(|ext| ctx.lower_path.ends_with(ext.as_str()));
                    if !extension_matches {
                        continue;
                    }
                }

                // 2. Filtrage par globs de chemin (not_in_path_matching prioritaire sur in_path_matching)
                if !compiled.not_in_path_regexes.is_empty() {
                    let excluded = compiled
                        .not_in_path_regexes
                        .iter()
                        .any(|re| re.is_match(norm_rel) || re.is_match(&norm_path));
                    if excluded {
                        continue;
                    }
                }
                if !compiled.in_path_regexes.is_empty() {
                    let included = compiled
                        .in_path_regexes
                        .iter()
                        .any(|re| re.is_match(norm_rel) || re.is_match(&norm_path));
                    if !included {
                        continue;
                    }
                }

                let eval_content = if rule.conditions.check_literals {
                    ctx.raw
                } else {
                    ctx.default_masked()
                };

                // 3. Vérification des conditions must_contain sur le fichier complet
                let has_all_must_contain = rule
                    .conditions
                    .must_contain
                    .iter()
                    .all(|pat| eval_content.contains(pat));
                if !rule.conditions.must_contain.is_empty() && !has_all_must_contain {
                    continue;
                }

                // 4. Vérification des conditions must_not_contain sur le fichier complet
                let has_any_mitigation = rule
                    .conditions
                    .must_not_contain
                    .iter()
                    .any(|pat| eval_content.contains(pat));
                if has_any_mitigation {
                    continue;
                }

                // 5. Exécution selon le mode
                match rule.match_mode {
                    MatchMode::WholeFile => {
                        let mut triggered = false;
                        for token in &rule.conditions.forbidden_tokens {
                            if eval_content.contains(token) {
                                triggered = true;
                                break;
                            }
                        }
                        if !triggered {
                            for re in &compiled.trigger_regexes {
                                if re.is_match(eval_content) {
                                    triggered = true;
                                    break;
                                }
                            }
                        }
                        if !triggered
                            && rule.conditions.forbidden_tokens.is_empty()
                            && compiled.trigger_regexes.is_empty()
                            && !rule.conditions.must_contain.is_empty()
                        {
                            triggered = true;
                        }
                        if triggered && seen_rule_lines.insert((rule.id.clone(), 1)) {
                            violations.push(LinterViolation {
                                file_path: ctx.file_path.to_string(),
                                line_number: 1,
                                rule_id: rule.id.clone(),
                                cve_id: rule.cwe_id.clone(),
                                severity: rule.severity.clone(),
                                message: format!("[Plugin: {}] {}", plugin.name, rule.description),
                                transmitted_data: None,
                                transmitted_type: None,
                                remediation: rule.remediation.clone(),
                            });
                        }
                    }
                    MatchMode::LineByLine => {
                        let eval_lines = if rule.conditions.check_literals {
                            raw_lines_cell.get_or_init(|| ctx.raw.lines().collect())
                        } else {
                            masked_lines_cell.get_or_init(|| ctx.default_masked().lines().collect())
                        };

                        let scopes_opt = rule.conditions.ast_scope.as_ref().map(|req_scope| {
                            let raw_l = raw_lines_cell.get_or_init(|| ctx.raw.lines().collect());
                            let scopes = ast_scopes_cell
                                .get_or_init(|| compute_line_ast_scopes(raw_l, &ctx.lower_path));
                            (req_scope.as_str(), scopes.as_slice())
                        });

                        let fallback_must_contain = rule.conditions.forbidden_tokens.is_empty()
                            && compiled.trigger_regexes.is_empty()
                            && !rule.conditions.must_contain.is_empty();

                        for (idx, &line) in eval_lines.iter().enumerate() {
                            if let Some((req_scope, scopes)) = scopes_opt {
                                if let Some(&sc) = scopes.get(idx) {
                                    if !scope_matches(req_scope, sc) {
                                        continue;
                                    }
                                }
                            }

                            let mut line_triggered = false;

                            for token in &rule.conditions.forbidden_tokens {
                                if line.contains(token) {
                                    line_triggered = true;
                                    break;
                                }
                            }

                            if !line_triggered {
                                for re in &compiled.trigger_regexes {
                                    if re.is_match(line) {
                                        line_triggered = true;
                                        break;
                                    }
                                }
                            }

                            if !line_triggered && fallback_must_contain
                                && rule
                                    .conditions
                                    .must_contain
                                    .iter()
                                    .any(|pat| line.contains(pat))
                                {
                                    line_triggered = true;
                                }

                            if line_triggered {
                                // Vérification de la fenêtre contextuelle not_preceded_within_lines
                                if let Some(ref win) = rule.conditions.not_preceded_within_lines {
                                    if win.lines > 0 && idx > 0 {
                                        let start_idx = idx.saturating_sub(win.lines);
                                        let raw_l = raw_lines_cell
                                            .get_or_init(|| ctx.raw.lines().collect());
                                        let preceded_by_guard =
                                            (start_idx..idx).any(|prev_idx| {
                                                let prev_eval =
                                                    eval_lines.get(prev_idx).copied().unwrap_or("");
                                                let prev_raw =
                                                    raw_l.get(prev_idx).copied().unwrap_or("");
                                                compiled.window_regexes.iter().any(|re| {
                                                    re.is_match(prev_eval) || re.is_match(prev_raw)
                                                }) || win.patterns.iter().any(|pat| {
                                                    prev_eval.contains(pat) || prev_raw.contains(pat)
                                                })
                                            });
                                        if preceded_by_guard {
                                            continue;
                                        }
                                    }
                                }

                                let line_no = idx + 1;
                                if seen_rule_lines.insert((rule.id.clone(), line_no)) {
                                    violations.push(LinterViolation {
                                        file_path: ctx.file_path.to_string(),
                                        line_number: line_no,
                                        rule_id: rule.id.clone(),
                                        cve_id: rule.cwe_id.clone(),
                                        severity: rule.severity.clone(),
                                        message: format!(
                                            "[Plugin: {}] {}",
                                            plugin.name, rule.description
                                        ),
                                        transmitted_data: Some(line.trim().to_string()),
                                        transmitted_type: Some("Code Snippet Line".to_string()),
                                        remediation: rule.remediation.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        violations
    }

    /// Exécute les cas de tests unitaires intégrés aux plugins (sans clonage de `self.plugins`).
    pub fn run_test_suite(&self) -> PluginTestReport {
        let mut report = PluginTestReport::default();

        for plugin in &self.plugins {
            for rule in &plugin.rules {
                for test in &rule.test_cases {
                    report.total_tests += 1;
                    let violations = self.audit_file(&test.file_name, &test.code);
                    let found = violations.iter().any(|v| v.rule_id == rule.id);

                    if found == test.should_trigger {
                        report.passed += 1;
                    } else {
                        report.failed += 1;
                        let reason = if test.should_trigger {
                            format!(
                                "[FAIL] Plugin '{}' / Rule '{}' failed to trigger on test '{}' (expected violation)",
                                plugin.name, rule.id, test.name
                            )
                        } else {
                            format!(
                                "[FAIL] Plugin '{}' / Rule '{}' falsely triggered on test '{}' (expected clean)",
                                plugin.name, rule.id, test.name
                            )
                        };
                        report.failures.push(reason);
                    }
                }
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PLUGIN_YAML: &str = r#"
name: "ZeroDay-Solana-Guard"
version: "1.0.0"
author: "Security Research Team"
description: "Règles personnalisées pour Smart Contracts Solana et Rust Web3"
enabled: true
rules:
  - id: "SOLANA-ACCOUNT-OWNERSHIP-BYPASS"
    cwe_id: "CWE-285 / MISSING-OWNER-CHECK"
    name: "Omission de vérification du Owner d'un compte Solana"
    category: "Web3 / Solana"
    severity: "CRITICAL"
    description: "Compte désérialisé sans validation de `account.owner == program_id`"
    remediation: "Ajoutez `if account.owner != program_id { return Err(ProgramError::IllegalOwner); }`"
    file_extensions: [".rs"]
    match_mode: "line_by_line"
    conditions:
      must_contain: ["AccountInfo"]
      must_not_contain: ["IllegalOwner", "owner =="]
      regex_patterns:
        - "try_from_slice\\(&account\\.data\\.borrow\\(\\)\\)"
    test_cases:
      - name: "Vulnérable - pas de vérification de owner"
        file_name: "instruction.rs"
        should_trigger: true
        code: |
          use solana_program::account_info::AccountInfo;
          pub fn process(account: &AccountInfo) {
              let state = MyState::try_from_slice(&account.data.borrow()).unwrap();
          }
      - name: "Sécurisé - vérification présente"
        file_name: "instruction.rs"
        should_trigger: false
        code: |
          use solana_program::account_info::AccountInfo;
          pub fn process(account: &AccountInfo) {
              if account.owner == program_id {
                  let state = MyState::try_from_slice(&account.data.borrow()).unwrap();
              }
          }
"#;

    #[test]
    fn test_plugin_loading_and_audit() {
        let mut engine = PluginEngine::new();
        engine
            .load_from_str(SAMPLE_PLUGIN_YAML)
            .expect("YAML parsing should succeed");

        assert_eq!(engine.plugins.len(), 1);
        let defs = engine.get_cve_rule_defs();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].rule_id, "SOLANA-ACCOUNT-OWNERSHIP-BYPASS");

        let report = engine.run_test_suite();
        assert_eq!(report.total_tests, 2);
        assert_eq!(report.passed, 2);
        assert_eq!(report.failed, 0);
    }
}
