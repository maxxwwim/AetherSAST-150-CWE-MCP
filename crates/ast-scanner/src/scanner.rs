use core_graph::bubble::{CveAnomalyRecord, SymbolBubble, SymbolKind};
use core_graph::edge::{AffiliationEdge, EdgeType, FilterAffiliation};
use core_graph::graph::AetherGraph;
use core_graph::layout::compute_all_layouts;
use core_graph::manifest::ProjectManifest;
use rayon::prelude::*;
use regex::Regex;
use security_linter::contract::ReadmeContract;
use security_linter::linter::SecurityLinter;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use walkdir::WalkDir;

pub use crate::lang::csharp::{analyze_csharp, analyze_csharp_symbols};
pub use crate::lang::zig::{analyze_zig, analyze_zig_symbols, strip_zig_inline_tests};

macro_rules! static_regex {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new($pattern).expect("Invalid static regex"))
        }
    };
}

static_regex!(
    re_complexity,
    r#"(?:\b(?:if|else|elif|match|for|while|loop|catch|case)\b|&&|\|\|)"#
);

pub fn compute_complexity(slice: &str) -> u32 {
    let branches = re_complexity().find_iter(slice).count() as u32;
    1 + branches
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RawCall {
    pub caller: String,
    pub callee: String,
    pub relation: String,
    pub order_label: String,
}

pub struct FileAnalysis {
    pub rel_path: String,
    pub folder: String,
    pub raw_content: String,
    pub nodes: Vec<SymbolBubble>,
    pub calls: Vec<RawCall>,
    pub routes_declared: Vec<(String, String)>,
    pub routes_called: Vec<(String, String)>,
    pub ws_handlers: Vec<(String, String)>,
    pub ws_emits: Vec<(String, String)>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachedFileScan {
    pub rel_path: String,
    pub folder: String,
    pub file_hash: String,
    pub contract_folder: Option<String>,
    pub nodes: Vec<SymbolBubble>,
    pub calls: Vec<RawCall>,
    pub routes_declared: Vec<(String, String)>,
    pub routes_called: Vec<(String, String)>,
    pub ws_handlers: Vec<(String, String)>,
    pub ws_emits: Vec<(String, String)>,
    pub violations: Vec<security_linter::linter::LinterViolation>,
}

#[derive(Debug, Clone)]
pub struct ProjectScanner {
    pub plugin_selection: security_linter::PluginSelection,
    pub use_cache: bool,
}

impl Default for ProjectScanner {
    fn default() -> Self {
        Self {
            plugin_selection: security_linter::PluginSelection::Default,
            use_cache: true,
        }
    }
}

impl ProjectScanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_plugin_selection(mut self, selection: security_linter::PluginSelection) -> Self {
        self.plugin_selection = selection;
        self
    }

    pub fn validate_plugins<P: AsRef<Path>>(
        &self,
        root: P,
    ) -> Result<security_linter::PluginEngine, String> {
        let plugins_dir = root.as_ref().join(".aether").join("plugins");
        let mut engine = security_linter::PluginEngine::new();
        engine.load_with_selection(Some(&plugins_dir), &self.plugin_selection)?;
        Ok(engine)
    }

    pub fn scan_project<P: AsRef<Path>>(&self, root: P) -> AetherGraph {
        self.scan_project_with_exclusions(root, &[])
    }

    pub fn scan_project_with_exclusions<P: AsRef<Path>>(
        &self,
        root: P,
        custom_exclusions: &[String],
    ) -> AetherGraph {
        let root_path = root.as_ref();
        let t0 = std::time::Instant::now();
        let project_name = root_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "AetherProject".to_string());

        let mut graph = AetherGraph::new(&project_name);
        graph.project_path = Some(root_path.to_string_lossy().to_string());

        let rules_file = root_path.join("AETHER_AI_RULES.md");
        if let Ok(rules_txt) = std::fs::read_to_string(&rules_file) {
            graph.system_prompt = Some(rules_txt);
        }

        let matches_wildcard = |pattern: &str, text: &str| -> bool {
            let tokens: Vec<&str> = pattern.split('*').collect();
            if tokens.len() == 1 {
                return pattern == text;
            }
            let mut rest = text;
            for (i, &token) in tokens.iter().enumerate() {
                if token.is_empty() {
                    continue;
                }
                if i == 0 {
                    if !rest.starts_with(token) {
                        return false;
                    }
                    rest = &rest[token.len()..];
                } else if i == tokens.len() - 1 {
                    return rest.ends_with(token);
                } else {
                    if let Some(pos) = rest.find(token) {
                        rest = &rest[pos + token.len()..];
                    } else {
                        return false;
                    }
                }
            }
            true
        };

        let is_excluded_custom = |path: &Path, rel_str: &str| -> bool {
            if custom_exclusions.is_empty() {
                return false;
            }
            let norm_rel = rel_str.replace('\\', "/").to_lowercase();
            let file_name = path
                .file_name()
                .map(|s| s.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            for pattern in custom_exclusions {
                let pat = pattern.trim().trim_start_matches('/').trim_end_matches('/').to_lowercase();
                if pat.is_empty() {
                    continue;
                }
                // Match directory component: e.g. "tests", "test", "mocks"
                if norm_rel.split('/').any(|comp| comp == pat) {
                    return true;
                }
                // Prefix or contains match for folder paths: e.g. "tests" or "src/tests"
                if norm_rel.starts_with(&pat)
                    || norm_rel.contains(&format!("/{}/", pat))
                    || norm_rel.ends_with(&format!("/{}", pat))
                {
                    return true;
                }
                // Wildcard pattern matching on filename or relative path
                if pat.contains('*') {
                    if matches_wildcard(&pat, &file_name) || matches_wildcard(&pat, &norm_rel) {
                        return true;
                    }
                } else if file_name == pat || norm_rel == pat {
                    return true;
                }
            }
            false
        };

        // Detect if the target workspace is a Rust-centric project (root or workspace subcrates)
        let is_rust_project = root_path.join("Cargo.toml").exists()
            || root_path.join("Cargo.lock").exists()
            || root_path.join("client/Cargo.toml").exists()
            || root_path.join("common/Cargo.toml").exists()
            || root_path.join("eddie_hvnc/Cargo.toml").exists()
            || root_path.join("server/Cargo.toml").exists()
            || root_path.join("server/src-tauri/Cargo.toml").exists()
            || root_path.join("src-tauri/Cargo.toml").exists()
            || root_path.join("crates").is_dir();

        let exclude_dirs = [
            ".git",
            ".github",
            ".gitlab",
            ".aether",
            "node_modules",
            "target",
            "dist",
            "build",
            "out",
            ".next",
            ".nuxt",
            ".svelte-kit",
            ".turbo",
            ".vercel",
            "venv",
            ".venv",
            "env",
            "__pycache__",
            ".tox",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".vscode",
            ".idea",
            ".vs",
            ".tauri_installer_assets_staging",
            "cosmoscope_output",
            "coverage",
            ".cache",
            "cache",
            "var",
            "tmp",
            "temp",
            "vendor",
            "third_party",
            "external",
            "bower_components",
            "bin",
            "obj",
            ".cargo",
            ".rustup",
            "logs",
            "log",
            "site-packages",
            ".terraform",
            "pkg",
            "wasm",
            "debug",
            "release",
            "pytest",
            "benchmarks",
            "benches",
            "examples",
            "samples",
            "demos",
            "fixtures",
            "testdata",
            "test_data",
            "debug_scripts",
            "integration-tests",
            "test-loop-tests",
            "test-utils",
            "testlib",
            "test-contracts",
            "runtime-params-estimator",
            "jsonrpc-adversarial-primitives",
            "genesis-tools",
            "tools",
            "scripts",
            "fuzz",
            "nightly",
            // Embedded C/C++ toolchains, SDKs & static libraries (e.g. w64devkit / MinGW)
            "w64devkit",
            "mingw64",
            "mingw32",
            "msys64",
            "x86_64-w64-mingw32",
            "i686-w64-mingw32",
            "cmake",
            "llvm",
            "clang",
            "include",
            "libexec",
            "share",
            // Vendored / auxiliary non-Rust subprojects & static assets
            "libs",
            "client_apk",
            "client_c",
            "cpp_builder",
            "python_utils_testing",
            "stub",
            "bindings",
            "protos",
            "privileges_scripts",
            "res",
            "resources",
            "assets",
            "static",
            "public",
            "imgs",
            "images",
            "icons",
            "fonts",
            "country_flags",
            "media",
            "audio",
            "sounds",
            "locales",
            "i18n",
            "translations",
            "capabilities",
            "gen",
            "schemas",
            "docs",
            "doc",
        ];

        let mut candidate_files = Vec::new();
        // Tous les fichiers non exclus (code ou non) : sert aux règles de contrat extensions / max fichiers
        let mut contract_scope_files: Vec<String> = Vec::new();
        for entry in WalkDir::new(root_path)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                let rel = e.path().strip_prefix(root_path).unwrap_or(e.path()).to_string_lossy();
                !name.starts_with('.')
                    && !exclude_dirs.iter().any(|d| name.eq_ignore_ascii_case(d))
                    && !name.contains("WebView2")
                    && !name.contains(".tmp")
                    && !is_excluded_custom(e.path(), &rel)
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let rel = entry.path().strip_prefix(root_path).unwrap_or(entry.path()).to_string_lossy();
            if is_excluded_custom(entry.path(), &rel) {
                continue;
            }
            // [SÉCURITÉ V2 / SECRET GUARD] Jamais de secrets/.env/clés dans le graphe ni dans l'analyse
            if security_linter::SecretGuard::is_secret_path(&*rel) {
                continue;
            }            contract_scope_files.push(rel.replace('\\', "/"));
            if let Ok(meta) = entry.metadata() {
                if meta.len() > 1_500_000 {
                    continue;
                }
            }
            let file_name = entry.file_name().to_string_lossy();
            let file_name_lower = file_name.to_lowercase();
            if file_name_lower.ends_with(".min.js")
                || file_name_lower.ends_with(".bundle.js")
                || file_name_lower.ends_with(".d.ts")
                || file_name_lower == "build.rs"
                || file_name_lower == "test.rs"
                || file_name_lower == "tests.rs"
                || file_name_lower.starts_with("temp_")
                || file_name_lower.starts_with("test_")
                || file_name_lower.starts_with("e2e_")
                || file_name_lower.ends_with("_test.rs")
                || file_name_lower.ends_with("_tests.rs")
                || file_name_lower.ends_with("_check.rs")
            {
                continue;
            }
            let ext = entry
                .path()
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            // For markdown files, only scan README.md architectural contracts
            if ext == "md" && file_name_lower != "readme.md" {
                continue;
            }
            // In Rust-centric projects, skip C/C++ toolchain/FFI files and Python scratch scripts
            if is_rust_project
                && matches!(
                    ext.as_str(),
                    "c" | "h" | "cpp" | "hpp" | "cc" | "hh" | "cxx" | "hxx" | "inl" | "py"
                )
            {
                continue;
            }
            if [
                "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "svelte", "vue", "py", "md", "cpp",
                "hpp", "cc", "hh", "cxx", "hxx", "c", "h", "inl", "sol", "yul", "php", "phtml",
                "php3", "php4", "php5", "php7", "phps", "java", "lua", "luau", "zig", "cs",
            ]
            .contains(&ext.as_str())
            {
                candidate_files.push(entry.path().to_path_buf());
            }
        }

        candidate_files.sort();
        let files_scanned = candidate_files.len();

        // Load aether.lock.toml if present to verify BLAKE3 contract hashes
        let mut locked_hashes: HashMap<String, String> = HashMap::new();
        let lock_path = root_path.join("aether.lock.toml");
        if let Ok(lock_str) = fs::read_to_string(&lock_path) {
            if let Ok(manifest) = toml::from_str::<ProjectManifest>(&lock_str) {
                for (gal_key, gal_cfg) in manifest.galaxies {
                    if let Some(h) = gal_cfg.readme_blake3 {
                        let norm_path = gal_cfg
                            .path
                            .trim_start_matches("./")
                            .trim_start_matches('/')
                            .replace('\\', "/");
                        locked_hashes.insert(norm_path, h.clone());
                        locked_hashes.insert(gal_key, h);
                    }
                }
            }
        }

        // Pre-parse README.md contracts across all folders before parallel code scanning
        let mut contracts_by_folder: HashMap<String, ReadmeContract> = HashMap::new();
        for path in &candidate_files {
            let is_readme = path
                .file_name()
                .map(|n| n.to_string_lossy().eq_ignore_ascii_case("readme.md"))
                .unwrap_or(false);
            if is_readme {
                if let Ok(raw_content) = fs::read_to_string(path) {
                    let rel_path = path
                        .strip_prefix(root_path)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    let folder = folder_from_rel_path(&rel_path);
                    if let Ok(contract) = ReadmeContract::parse(&folder, &raw_content) {
                        contracts_by_folder.insert(folder, contract);
                    }
                }
            }
        }

        let find_contract_for_folder = |folder: &str| -> Option<&ReadmeContract> {
            if let Some(c) = contracts_by_folder.get(folder) {
                return Some(c);
            }
            let mut cur = folder;
            while let Some(idx) = cur.rfind('/') {
                cur = &cur[..idx];
                if let Some(c) = contracts_by_folder.get(cur) {
                    return Some(c);
                }
            }
            contracts_by_folder.get("root")
        };

        let find_contract_for_file = |folder: &str, file_path: &str| -> Option<&ReadmeContract> {
            if let Some(c) = contracts_by_folder.get(folder) {
                if c.file_override_for(file_path).is_some() {
                    return Some(c);
                }
            }
            let mut cur = folder;
            while let Some(idx) = cur.rfind('/') {
                cur = &cur[..idx];
                if let Some(c) = contracts_by_folder.get(cur) {
                    if c.file_override_for(file_path).is_some() {
                        return Some(c);
                    }
                }
            }
            if let Some(root_c) = contracts_by_folder.get("root") {
                if root_c.file_override_for(file_path).is_some() {
                    return Some(root_c);
                }
            }
            find_contract_for_folder(folder)
        };

        // Initialize lock-free PluginEngine (Send + Sync) according to self.plugin_selection
        let plugins_dir = root_path.join(".aether").join("plugins");
        let mut plugin_engine = security_linter::PluginEngine::new();
        let _ = plugin_engine.load_with_selection(
            if plugins_dir.is_dir() {
                Some(&plugins_dir)
            } else {
                None
            },
            &self.plugin_selection,
        );
        let plugin_digest = plugin_engine.config_digest();
        let taint_rules = plugin_engine.collect_taint_rules();
        let has_taint_rules = !taint_rules.is_empty();
        let has_plugin_rules = plugin_engine.total_rules_count() > 0;
        let run_builtin_sast = !matches!(
            self.plugin_selection,
            security_linter::PluginSelection::Select(_)
        );

        let ast_cache_dir = root_path.join(".aether").join("cache").join("ast");
        if self.use_cache && !candidate_files.is_empty() {
            let _ = fs::create_dir_all(&ast_cache_dir);
        }

        // Parallel AST + SAST scan with deterministic BLAKE3 per-file incremental cache
        let scanned_entries: Vec<(CachedFileScan, Option<String>, String)> = candidate_files
            .par_iter()
            .filter_map(|path| {
                let content = fs::read_to_string(path).ok()?;
                let rel_path = path
                    .strip_prefix(root_path)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let folder = folder_from_rel_path(&rel_path);
                let ext = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                let file_hash = ReadmeContract::compute_blake3_hex(&content);
                let contract = find_contract_for_file(&folder, &rel_path);
                let contract_folder = contract.map(|c| c.folder_path.clone());
                let contract_sig = match contract {
                    Some(c) => format!(
                        "{}:{}:{}",
                        c.folder_path,
                        c.blake3_hash,
                        c.effective_max_lines(&rel_path)
                    ),
                    None => "none".to_string(),
                };
                let entry_key = ReadmeContract::compute_blake3_hex(&format!(
                    "v2|{}|{}|{}|{}",
                    rel_path, file_hash, contract_sig, plugin_digest
                ));
                let cache_file_name = format!("{}.json", entry_key);
                let cache_file_path = ast_cache_dir.join(&cache_file_name);

                if self.use_cache && cache_file_path.is_file() {
                    if let Ok(bytes) = fs::read(&cache_file_path) {
                        if let Ok(cached) = serde_json::from_slice::<CachedFileScan>(&bytes) {
                            let taint_src = if has_taint_rules && ext != "md" {
                                Some(content)
                            } else {
                                None
                            };
                            return Some((cached, taint_src, cache_file_name));
                        }
                    }
                }

                let res = analyze_file_with_content(&rel_path, &ext, &content)?;
                let mut violations = Vec::new();
                if ext != "md" {
                    let ctx = security_linter::lexer::AuditContext::new(&rel_path, &content);
                    if run_builtin_sast {
                        violations.extend(SecurityLinter::audit_file_with_context(&ctx, contract));
                    }
                    if has_plugin_rules {
                        violations.extend(plugin_engine.audit_file_with_context(&ctx));
                    }
                }

                let scan_entry = CachedFileScan {
                    rel_path,
                    folder,
                    file_hash,
                    contract_folder,
                    nodes: res.nodes,
                    calls: res.calls,
                    routes_declared: res.routes_declared,
                    routes_called: res.routes_called,
                    ws_handlers: res.ws_handlers,
                    ws_emits: res.ws_emits,
                    violations,
                };

                if self.use_cache {
                    if let Ok(json_bytes) = serde_json::to_vec(&scan_entry) {
                        let tmp_name = format!(
                            ".tmp_{}_{}_{}.json",
                            entry_key,
                            std::process::id(),
                            rayon::current_thread_index().unwrap_or(0)
                        );
                        let tmp_path = ast_cache_dir.join(tmp_name);
                        if fs::write(&tmp_path, &json_bytes).is_ok() {
                            if fs::rename(&tmp_path, &cache_file_path).is_err() {
                                let _ = fs::write(&cache_file_path, &json_bytes);
                                let _ = fs::remove_file(&tmp_path);
                            }
                        } else {
                            let _ = fs::write(&cache_file_path, &json_bytes);
                        }
                    }
                }

                let taint_src = if has_taint_rules && ext != "md" {
                    Some(content)
                } else {
                    None
                };
                Some((scan_entry, taint_src, cache_file_name))
            })
            .collect();

        let mut active_cache_files: HashSet<String> = HashSet::with_capacity(scanned_entries.len());
        let mut all_raw_calls = Vec::new();
        let mut routes_declared = Vec::new();
        let mut routes_called = Vec::new();
        let mut ws_handlers = Vec::new();
        let mut ws_emits = Vec::new();
        let mut file_hashes: HashMap<String, String> = HashMap::with_capacity(scanned_entries.len());
        let mut parallel_violations: Vec<(
            String,
            Option<String>,
            Vec<security_linter::linter::LinterViolation>,
        )> = Vec::new();
        let mut taint_files: Vec<(String, String)> = Vec::new();

        for (entry, taint_src, cache_file_name) in scanned_entries {
            active_cache_files.insert(cache_file_name);
            file_hashes.insert(entry.rel_path.clone(), entry.file_hash);
            if let Some(raw_src) = taint_src {
                taint_files.push((entry.rel_path.clone(), raw_src));
            }
            if !entry.violations.is_empty() {
                parallel_violations.push((
                    entry.rel_path.clone(),
                    entry.contract_folder,
                    entry.violations,
                ));
            }
            graph.nodes.extend(entry.nodes);
            all_raw_calls.extend(entry.calls);
            routes_declared.extend(entry.routes_declared);
            routes_called.extend(entry.routes_called);
            ws_handlers.extend(entry.ws_handlers);
            ws_emits.extend(entry.ws_emits);
        }

        // Garbage-collect stale BLAKE3 cache entries in .aether/cache/ast/ after a full scan
        if self.use_cache && custom_exclusions.is_empty() && ast_cache_dir.is_dir() {
            if let Ok(entries) = fs::read_dir(&ast_cache_dir) {
                for dir_entry in entries.filter_map(|e| e.ok()) {
                    let fname = dir_entry.file_name().to_string_lossy().to_string();
                    if fname.ends_with(".json")
                        && !fname.starts_with(".tmp_")
                        && !active_cache_files.contains(&fname)
                    {
                        let _ = fs::remove_file(dir_entry.path());
                    }
                }
            }
        }

        // Run SSA Dataflow Taint Extraction while raw source strings are available, then drop immediately
        if has_taint_rules && !taint_files.is_empty() {
            let taint_refs: Vec<(&str, &str)> = taint_files
                .iter()
                .map(|(p, c)| (p.as_str(), c.as_str()))
                .collect();
            let dfg = crate::taint_extractor::TaintExtractor::extract_multi_with_rules(
                &taint_refs,
                &taint_rules,
            );
            graph.dataflow_graph = Some(dfg);
        }
        drop(taint_files);

        // Resolve AST edges (contains, imports, calls, renders, inherits, network, submits, documents)
        let resolved_edges = resolve_graph_edges(&mut graph.nodes, &all_raw_calls);
        drop(all_raw_calls);
        graph.edges.extend(resolved_edges);

        // Enrich all nodes with their folder/file BLAKE3 hash, lock status, EARS count & max lines limit
        let mut tamper_edges: Vec<AffiliationEdge> = Vec::new();
        for node in &mut graph.nodes {
            node.metadata.file_blake3_hash = file_hashes.get(&node.file_path).cloned();
            if let Some(contract) = find_contract_for_file(&node.folder, &node.file_path) {
                node.metadata.blake3_hash = Some(contract.blake3_hash.clone());
                node.metadata.contract_folder = Some(contract.folder_path.clone());
                node.metadata.ears_count = contract.ears_requirements.len();
                node.metadata.max_lines_limit = Some(contract.effective_max_lines(&node.file_path));
                node.metadata.file_max_lines_override = contract.file_override_for(&node.file_path);
                let expected = locked_hashes
                    .get(&contract.folder_path)
                    .or_else(|| locked_hashes.get(&node.folder))
                    .or_else(|| locked_hashes.get(&node.galaxy));
                if let Some(exp_hash) = expected {
                    let verified = contract.verify_lock(exp_hash);
                    node.metadata.lock_verified = Some(verified);
                    if !verified && node.file_path.to_lowercase().ends_with("readme.md") {
                        node.has_security_violation = true;
                        let msg = format!(
                            "[BLAKE3_TAMPERED] Contrat {} modifié sans signature dans aether.lock.toml (attendu: {}…, actuel: {}…)",
                            node.file_path,
                            &exp_hash[..exp_hash.len().min(8)],
                            &contract.blake3_hash[..contract.blake3_hash.len().min(8)]
                        );
                        let anomaly = CveAnomalyRecord {
                            rule_id: "BLAKE3_TAMPERED".to_string(),
                            cve_id: "CWE-353 / BLAKE3-INTEGRITY".to_string(),
                            severity: "CRITICAL".to_string(),
                            line_number: 1,
                            file_path: node.file_path.clone(),
                            message: msg.clone(),
                            transmitted_data: Some("contract_readme_hash".to_string()),
                            transmitted_type: Some("BLAKE3 (Tampered Hash Mismatch)".to_string()),
                            remediation: "Re-sign contract with AetherScope or revert unauthorized modifications.".to_string(),
                            ..Default::default()
                        };
                        node.metadata.violations.push(msg.clone());
                        node.metadata.cve_anomalies.push(anomaly);
                        tamper_edges.push(AffiliationEdge::new_cve_violation(
                            node.id.clone(),
                            node.id.clone(),
                            &msg,
                            Some("CWE-353 / BLAKE3-INTEGRITY".to_string()),
                            Some("CRITICAL".to_string()),
                            Some("contract_readme_hash".to_string()),
                            Some("BLAKE3 (Tampered Hash Mismatch)".to_string()),
                        ));
                    }
                }
            }
        }
        graph.edges.extend(tamper_edges);

        // Règles de contrat « structure » : extensions interdites (fichiers non scannés) et nombre max de fichiers par dossier.
        // Les fichiers de code scannés reçoivent RULE_FORBIDDEN_EXTENSION directement via le linter.
        {
            let scanned_rel: HashSet<String> = candidate_files
                .iter()
                .map(|p| {
                    p.strip_prefix(root_path)
                        .unwrap_or(p)
                        .to_string_lossy()
                        .replace('\\', "/")
                })
                .collect();
            let readme_rel_of = |c: &ReadmeContract| -> String {
                if c.folder_path == "root" || c.folder_path.is_empty() {
                    "README.md".to_string()
                } else {
                    format!("{}/README.md", c.folder_path.trim_matches('/'))
                }
            };
            let mut files_per_folder: HashMap<String, usize> = HashMap::new();
            let mut structure_violations: Vec<(
                String,
                Option<String>,
                Vec<security_linter::linter::LinterViolation>,
            )> = Vec::new();
            for rel in &contract_scope_files {
                let name_lower = rel.rsplit('/').next().unwrap_or(rel).to_lowercase();
                if name_lower == "readme.md" {
                    continue;
                }
                let folder = folder_from_rel_path(rel);
                let Some(contract) = find_contract_for_folder(&folder) else {
                    continue;
                };
                *files_per_folder.entry(folder.clone()).or_insert(0) += 1;
                if scanned_rel.contains(rel) {
                    continue;
                }
                if let Some(mut v) = SecurityLinter::contract_extension_violation(rel, contract) {
                    // Pas de nœud pour ce fichier : l'alerte est portée par le README du contrat.
                    let anchor = readme_rel_of(contract);
                    v.file_path = anchor.clone();
                    structure_violations.push((anchor, Some(contract.folder_path.clone()), vec![v]));
                }
            }
            let mut folders_sorted: Vec<(&String, &usize)> = files_per_folder.iter().collect();
            folders_sorted.sort();
            for (folder, count) in folders_sorted {
                let Some(contract) = find_contract_for_folder(folder) else {
                    continue;
                };
                let anchor = readme_rel_of(contract);
                if let Some(v) =
                    SecurityLinter::contract_max_files_violation(&anchor, folder, *count, contract)
                {
                    structure_violations.push((anchor, Some(contract.folder_path.clone()), vec![v]));
                }
            }
            parallel_violations.extend(structure_violations);
        }
        // Pre-index node indices by file_path and by node ID for instant O(1) lookup during violation mapping
        let mut nodes_by_file: HashMap<String, Vec<usize>> = HashMap::new();
        let mut node_idx_by_id: HashMap<String, usize> = HashMap::with_capacity(graph.nodes.len());
        for (idx, n) in graph.nodes.iter().enumerate() {
            nodes_by_file.entry(n.file_path.clone()).or_default().push(idx);
            node_idx_by_id.insert(n.id.clone(), idx);
        }

        let mut linter_edges: Vec<AffiliationEdge> = Vec::new();
        for (rel_path, contract_folder, violations) in parallel_violations {
            let file_node_id = format!("file::{}", rel_path);
            let readme_target_id = contract_folder
                .map(|cf| {
                    if cf == "root" {
                        "file::README.md".to_string()
                    } else {
                        format!("file::{}/README.md", cf)
                    }
                })
                .unwrap_or_else(|| file_node_id.clone());

            let file_node_indices = nodes_by_file.get(&rel_path);
            let has_readme_target = node_idx_by_id.contains_key(&readme_target_id);

            for v in violations {
                let formatted = format!(
                    "[{}] ({} | {}) L{}: {} — Fix: {}",
                    v.rule_id, v.cve_id, v.severity, v.line_number, v.message, v.remediation
                );

                let anomaly_rec = CveAnomalyRecord {
                    rule_id: v.rule_id.clone(),
                    cve_id: v.cve_id.clone(),
                    severity: v.severity.clone(),
                    line_number: v.line_number,
                    file_path: v.file_path.clone(),
                    message: v.message.clone(),
                    transmitted_data: v.transmitted_data.clone(),
                    transmitted_type: v.transmitted_type.clone(),
                    remediation: v.remediation.clone(),
                    ..Default::default()
                };

                // Mark file node and closest symbol node in that file (RULE_MAX_LINES is strictly file-level, never attached to a symbol)
                let is_file_level_rule = matches!(
                    v.rule_id.as_str(),
                    "RULE_MAX_LINES" | "RULE_MAX_FILES" | "RULE_FORBIDDEN_EXTENSION"
                );
                let is_lines_warning = v.rule_id == "RULE_MAX_LINES"
                    || v.rule_id == "RULE_MAX_FILES"
                    || v.cve_id.contains("ARCH-BUDGET-EXCEEDED")
                    || v.cve_id.contains("CONTRACT / ARCH-BUDGET")
                    || v.cve_id == "CONTRACT_BUDGET"
                    || (v.severity == "WARNING"
                        && (v.rule_id.contains("LINE") || v.cve_id.contains("BUDGET")));
                let mut best_sym_id: Option<String> = None;
                let mut best_line = 0usize;

                if let Some(indices) = file_node_indices {
                    for &idx in indices {
                        let n = &mut graph.nodes[idx];
                        if n.is_file {
                            if !is_lines_warning {
                                n.has_security_violation = true;
                            }
                            n.metadata.violations.push(formatted.clone());
                        } else if !is_file_level_rule
                            && n.line_number <= v.line_number
                            && n.line_number >= best_line
                        {
                            best_line = n.line_number;
                            best_sym_id = Some(n.id.clone());
                        }
                    }
                }

                if let Some(sym_id) = best_sym_id.as_ref().filter(|_| !is_file_level_rule) {
                    if let Some(&sym_idx) = node_idx_by_id.get(sym_id) {
                        let sym_node = &mut graph.nodes[sym_idx];
                        if !is_lines_warning {
                            sym_node.has_security_violation = true;
                        }
                        sym_node.metadata.violations.push(formatted.clone());
                        sym_node.metadata.cve_anomalies.push(anomaly_rec.clone());
                    }
                } else if let Some(&file_idx) = node_idx_by_id.get(&file_node_id) {
                    graph.nodes[file_idx].metadata.cve_anomalies.push(anomaly_rec.clone());
                }

                let src_id = if is_file_level_rule {
                    file_node_id.clone()
                } else {
                    best_sym_id.unwrap_or_else(|| file_node_id.clone())
                };
                let tgt_id = if has_readme_target {
                    readme_target_id.clone()
                } else {
                    file_node_id.clone()
                };
                if is_lines_warning {
                    linter_edges.push(AffiliationEdge::new_warning(
                        src_id,
                        tgt_id,
                        &format!("{}: {}", v.rule_id, v.message),
                        Some(v.cve_id.clone()),
                        Some(v.severity.clone()),
                        v.transmitted_data.clone(),
                        v.transmitted_type.clone(),
                    ));
                } else {
                    linter_edges.push(AffiliationEdge::new_cve_violation(
                        src_id,
                        tgt_id,
                        &format!("{}: {}", v.rule_id, v.message),
                        Some(v.cve_id.clone()),
                        Some(v.severity.clone()),
                        v.transmitted_data.clone(),
                        v.transmitted_type.clone(),
                    ));
                }
            }
        }
        graph.edges.extend(linter_edges);

        // Evaluate SSA Dataflow Taint propagation and materialize vulnerable plugin taint sink findings
        if graph.dataflow_graph.is_some() {
            let taint_traces = graph.compute_dataflow_taint(&taint_rules.sanitizers);
            let mut taint_edges: Vec<AffiliationEdge> = Vec::new();
            for trace in taint_traces {
                if !trace.is_vulnerable || trace.is_sanitized {
                    continue;
                }
                let sink_file = &trace.sink.file_path;
                let sink_line = trace.sink.line;
                let rule_id = &trace.sink.rule_id;

                let mut already_attached = false;
                if let Some(indices) = nodes_by_file.get(sink_file) {
                    for &idx in indices {
                        for anom in &mut graph.nodes[idx].metadata.cve_anomalies {
                            if anom.rule_id == *rule_id && anom.line_number == sink_line {
                                anom.is_reachable = true;
                                if anom.exploit_path.is_empty() {
                                    anom.exploit_path = trace.traversed_scoped_variables();
                                }
                                if anom.taint_trace.is_none() {
                                    anom.taint_trace = Some(trace.clone());
                                }
                                already_attached = true;
                            }
                        }
                    }
                }

                if !already_attached {
                    let is_plugin_sink_rule = taint_rules
                        .sinks
                        .iter()
                        .any(|s| s.rule_id == *rule_id);
                    if !is_plugin_sink_rule {
                        continue;
                    }
                    let file_node_id = format!("file::{}", sink_file);
                    let msg = format!(
                        "Tainted dataflow from '{}' ({}:{}) reaches sink '{}' ({})",
                        trace.source.var.name,
                        trace.source.file_path,
                        trace.source.line,
                        trace.sink.var.name,
                        trace.sink.description
                    );
                    let remediation =
                        "Sanitize or parameterize untrusted input before passing to sink."
                            .to_string();
                    let formatted = format!(
                        "[{}] ({}) L{}: {} — Fix: {}",
                        rule_id, trace.sink.severity, sink_line, msg, remediation
                    );
                    let anomaly_rec = CveAnomalyRecord {
                        rule_id: rule_id.clone(),
                        cve_id: trace.sink.cwe.clone(),
                        severity: trace.sink.severity.clone(),
                        line_number: sink_line,
                        file_path: sink_file.clone(),
                        message: msg.clone(),
                        transmitted_data: Some(trace.sink.var.name.clone()),
                        transmitted_type: Some(format!("{:?}", trace.sink.sink_kind)),
                        remediation,
                        is_reachable: true,
                        exploit_path: trace.traversed_scoped_variables(),
                        taint_trace: Some(trace.clone()),
                    };

                    let mut best_sym_id: Option<String> = None;
                    let mut best_line = 0usize;
                    if let Some(indices) = nodes_by_file.get(sink_file) {
                        for &idx in indices {
                            let n = &mut graph.nodes[idx];
                            if n.is_file {
                                n.has_security_violation = true;
                                n.metadata.violations.push(formatted.clone());
                            } else if n.line_number <= sink_line && n.line_number >= best_line {
                                best_line = n.line_number;
                                best_sym_id = Some(n.id.clone());
                            }
                        }
                    }

                    if let Some(ref sym_id) = best_sym_id {
                        if let Some(&sym_idx) = node_idx_by_id.get(sym_id) {
                            let sym_node = &mut graph.nodes[sym_idx];
                            sym_node.has_security_violation = true;
                            sym_node.metadata.violations.push(formatted);
                            sym_node.metadata.cve_anomalies.push(anomaly_rec);
                        }
                    } else if let Some(&file_idx) = node_idx_by_id.get(&file_node_id) {
                        let file_node = &mut graph.nodes[file_idx];
                        file_node.has_security_violation = true;
                        file_node.metadata.cve_anomalies.push(anomaly_rec);
                    }

                    let src_id = best_sym_id.unwrap_or_else(|| file_node_id.clone());
                    taint_edges.push(AffiliationEdge::new_cve_violation(
                        src_id,
                        file_node_id,
                        &format!("{}: {}", rule_id, msg),
                        Some(trace.sink.cwe.clone()),
                        Some(trace.sink.severity.clone()),
                        Some(trace.sink.var.name.clone()),
                        Some(format!("{:?}", trace.sink.sink_kind)),
                    ));
                }
            }
            graph.edges.extend(taint_edges);
        }

        // Cross-Boundary Filter 2 : NetworkRPC Matcher (Client -> Server Laser Orange)
        for (call_route, client_id) in &routes_called {
            let norm_call = call_route.to_lowercase().replace('/', "_");
            for (route_name, server_id) in &routes_declared {
                if server_id.to_lowercase().contains(&norm_call)
                    || route_name.to_lowercase().contains(&norm_call)
                {
                    graph.add_edge(AffiliationEdge::new_rpc(
                        client_id.clone(),
                        server_id.clone(),
                        call_route,
                    ));
                }
            }
        }

        // Cross-Boundary Filter 3 : RealtimeWS Matcher (Client -> Server Laser Cyan)
        for (pkt_name, client_id) in &ws_emits {
            let norm_pkt = pkt_name.to_lowercase();
            for (handler_name, server_id) in &ws_handlers {
                if handler_name.to_lowercase().contains(&norm_pkt)
                    || server_id.to_lowercase().contains(&norm_pkt)
                {
                    graph.add_edge(AffiliationEdge::new_realtime(
                        client_id.clone(),
                        server_id.clone(),
                        pkt_name,
                    ));
                }
            }
        }

        // Compute the 4 mathematical layouts (Obsidian, System, Flow, Classes)
        compute_all_layouts(&mut graph.nodes);

        // Compute stats (degrees, dead code, layers, relations, sides)
        graph.stats.files_scanned = files_scanned;
        graph.compute_stats();
        graph.stats.elapsed_ms = t0.elapsed().as_millis();

        graph
    }
}

pub fn detect_galaxy(rel_path: &str) -> String {
    let fp = rel_path.replace('\\', "/").to_lowercase();
    if fp.starts_with("contracts") || fp.starts_with("shared") || fp.contains("/contracts/") {
        "contracts".to_string()
    } else if fp.starts_with("client") || fp.starts_with("frontend") || fp.starts_with("web") {
        "client".to_string()
    } else if fp.starts_with("server") || fp.starts_with("backend") {
        "server".to_string()
    } else if fp.starts_with("data-nodes") || fp.contains("/db/") || fp.contains("/database/") {
        "data-nodes".to_string()
    } else {
        "core".to_string()
    }
}

pub fn detect_layer(file_path: &str, name: &str) -> String {
    let fp = file_path.to_lowercase().replace('\\', "/");
    let nn = name.to_lowercase();

    if fp.ends_with(".md")
        || fp.contains("docs")
        || fp.contains("documentation")
        || nn.contains("readme")
    {
        "docs".to_string()
    } else if fp.contains("ui")
        || fp.contains("views")
        || fp.contains("components")
        || fp.contains("frontend")
        || fp.contains("dashboard")
        || fp.contains("renderer")
        || fp.contains("desktop-shell")
        || nn.contains("view")
        || nn.contains("page")
        || nn.contains("widget")
        || nn.contains("panel")
        || nn.contains("render")
        || nn.contains("card")
        || nn.contains("modal")
        || nn.contains("button")
    {
        "ui".to_string()
    } else if fp.contains("controllers")
        || fp.contains("handlers")
        || fp.contains("routes")
        || fp.contains("api")
        || fp.contains("endpoints")
        || fp.contains("cli")
        || fp.contains("actions")
        || fp.contains("hooks")
        || fp.contains("transport")
        || nn.contains("controller")
        || nn.contains("handler")
        || nn.contains("route")
        || nn.contains("command")
        || nn.contains("action")
    {
        "action".to_string()
    } else if fp.contains("models")
        || fp.contains("entities")
        || fp.contains("database")
        || fp.contains("db")
        || fp.contains("schemas")
        || fp.contains("repositories")
        || fp.contains("stores")
        || fp.contains("data-nodes")
        || nn.contains("model")
        || nn.contains("entity")
        || nn.contains("schema")
        || nn.contains("table")
        || nn.contains("store")
    {
        "database".to_string()
    } else if fp.contains("config")
        || fp.contains("settings")
        || fp.contains("env")
        || fp.contains("manifest")
        || nn.contains("config")
        || nn.contains("settings")
    {
        "config".to_string()
    } else if fp.contains("utils")
        || fp.contains("helpers")
        || fp.contains("tools")
        || fp.contains("common")
        || nn.contains("util")
        || nn.contains("helper")
        || nn.contains("format")
    {
        "utility".to_string()
    } else {
        "domain".to_string()
    }
}

pub fn detect_stereotype(name: &str, is_class: bool, layer: &str, bases: &[String]) -> String {
    let nn = name.to_lowercase();
    if nn.contains("form") || bases.iter().any(|b| b.to_lowercase().contains("form")) {
        return "«Form»".to_string();
    }
    if is_class {
        if nn.contains("model")
            || bases.iter().any(|b| b.to_lowercase().contains("model"))
            || layer == "database"
        {
            "«Model»".to_string()
        } else if nn.contains("service")
            || bases.iter().any(|b| b.to_lowercase().contains("service"))
        {
            "«Service»".to_string()
        } else if nn.contains("controller") || nn.contains("handler") {
            "«Controller»".to_string()
        } else if nn.contains("plugin") || bases.iter().any(|b| b.to_lowercase().contains("plugin")) {
            "«Plugin»".to_string()
        } else if nn.contains("listener") || bases.iter().any(|b| b.to_lowercase().contains("listener")) {
            "«Listener»".to_string()
        } else if nn.contains("view") || nn.contains("component") || layer == "ui" {
            "«Component»".to_string()
        } else if nn.contains("config") || nn.contains("manifest") {
            "«Config»".to_string()
        } else if nn.contains("helper") || nn.contains("util") {
            "«Utility»".to_string()
        } else {
            "«Class»".to_string()
        }
    } else if layer == "action" {
        "«Action»".to_string()
    } else if layer == "ui" {
        "«Component»".to_string()
    } else {
        "«Function»".to_string()
    }
}

pub(crate) fn folder_from_rel_path(rel_path: &str) -> String {
    Path::new(rel_path)
        .parent()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "root".to_string())
}

pub(crate) fn extract_leading_doc(content: &str, start_byte: usize, is_rust: bool) -> String {
    let end = start_byte.min(content.len());
    if end == 0 {
        return String::new();
    }
    // Only inspect up to the last 2048 bytes before start_byte to avoid O(N) whole-file allocations
    let mut win_start = end.saturating_sub(2048);
    while win_start < end && !content.is_char_boundary(win_start) {
        win_start += 1;
    }
    let prefix = &content[win_start..end];

    let mut collected = Vec::new();
    let mut in_block_comment = false;
    let mut skipped_blanks = 0;

    for raw_line in prefix.lines().rev() {
        let line = raw_line.trim();
        if line.is_empty() {
            if collected.is_empty() && skipped_blanks < 2 {
                skipped_blanks += 1;
                continue;
            } else {
                break;
            }
        }

        // Rust attributes: #[...], #![...]
        if is_rust && (line.starts_with("#[") || line.starts_with("#![") || line == "]") {
            continue;
        }
        // JS decorators: @...
        if !is_rust
            && line.starts_with('@')
            && !line.starts_with("@param")
            && !line.starts_with("@return")
            && !line.starts_with("@type")
        {
            continue;
        }

        if in_block_comment {
            if let Some(pos) = line.find("/*") {
                let part = line[pos + 2..].trim_start_matches('*').trim();
                if !part.is_empty() {
                    collected.push(part.to_string());
                }
                in_block_comment = false;
            } else {
                let part = line.trim_start_matches('*').trim();
                collected.push(part.to_string());
            }
            continue;
        }

        if line.ends_with("*/") {
            in_block_comment = true;
            if let Some(pos) = line.find("/*") {
                let inner = &line[pos + 2..line.len() - 2];
                let part = inner.trim_start_matches('*').trim();
                if !part.is_empty() {
                    collected.push(part.to_string());
                }
                in_block_comment = false;
            } else {
                let inner = line.strip_suffix("*/").unwrap_or(line);
                let part = inner.trim_start_matches('*').trim();
                if !part.is_empty() {
                    collected.push(part.to_string());
                }
            }
            continue;
        }

        // Line comments:
        if let Some(rest) = line.strip_prefix("///").or_else(|| line.strip_prefix("//!")) {
            collected.push(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("//") {
            collected.push(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix('#') {
            collected.push(rest.trim().to_string());
        } else {
            break;
        }
    }

    collected.reverse();
    collected.join("\n")
}

fn analyze_file_with_content(rel_path: &str, ext: &str, content: &str) -> Option<FileAnalysis> {
    set_active_line_index(content);
    match ext {
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "svelte" | "vue" => {
            Some(crate::lang::analyze_jsts(rel_path, content))
        }
        "py" => Some(crate::lang::analyze_python(rel_path, content)),
        "rs" => Some(crate::lang::analyze_rust(rel_path, content)),
        "cpp" | "hpp" | "cc" | "hh" | "cxx" | "hxx" | "c" | "h" | "inl" => {
            Some(crate::lang::analyze_cpp(rel_path, content))
        }
        "sol" | "yul" => Some(crate::lang::analyze_solidity(rel_path, content)),
        "md" => Some(crate::lang::analyze_markdown(rel_path, content)),
        "php" | "phtml" | "php3" | "php4" | "php5" | "php7" | "phps" => {
            Some(crate::lang::analyze_php(rel_path, content))
        }
        "java" => Some(crate::lang::analyze_java(rel_path, content)),
        "lua" | "luau" => Some(crate::lang::analyze_luau(rel_path, content)),
        "zig" => Some(crate::lang::analyze_zig(rel_path, content)),
        "cs" => Some(crate::lang::analyze_csharp(rel_path, content)),
        _ => None,
    }
}

/// Mots-clés de langage capturés à tort comme appels (`if (`, `foreach (`, `isset(`...).
/// Sans ce filtre, un faux symbole `if` (ex. jquery-ui.js) recevait ~18k arêtes `calls`
/// sur PrestaShop et noyait le graphe.
fn is_language_keyword_call(name: &str) -> bool {
    matches!(
        name,
        "if" | "elseif"
            | "else"
            | "for"
            | "foreach"
            | "while"
            | "switch"
            | "catch"
            | "function"
            | "return"
            | "do"
            | "try"
            | "isset"
            | "empty"
            | "unset"
            | "echo"
            | "exit"
            | "die"
            | "require"
            | "include"
            | "require_once"
            | "include_once"
    )
}

fn lang_family_of(file_path: &str) -> &'static str {
    let ext = Path::new(file_path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "rs" => "rust",
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "svelte" | "vue" => "web",
        "py" => "python",
        "cpp" | "hpp" | "cc" | "hh" | "cxx" | "hxx" | "c" | "h" | "inl" => "cpp",
        "sol" | "yul" => "solidity",
        "php" | "phtml" | "php3" | "php4" | "php5" | "php7" | "phps" => "php",
        "java" => "java",
        "lua" | "luau" => "luau",
        "zig" => "zig",
        "cs" => "csharp",
        "md" => "docs",
        _ => "other",
    }
}

pub fn resolve_graph_edges(
    nodes: &mut Vec<SymbolBubble>,
    raw_calls: &[RawCall],
) -> Vec<AffiliationEdge> {
    let mut node_idx_by_id: HashMap<String, usize> = HashMap::with_capacity(nodes.len() + 32);
    let mut node_by_filepath: HashMap<String, usize> = HashMap::new();
    let mut filepath_entries: Vec<(String, usize)> = Vec::new();
    let mut node_by_name: HashMap<String, usize> = HashMap::with_capacity(nodes.len());
    let mut node_by_lang_and_name: HashMap<(&'static str, String), usize> =
        HashMap::with_capacity(nodes.len());
    let mut db_node_flags: Vec<bool> = vec![false; nodes.len()];

    for (idx, n) in nodes.iter().enumerate() {
        node_idx_by_id.insert(n.id.clone(), idx);
        let lang = lang_family_of(&n.file_path);

        if n.layer == "database"
            || n.folder == "data-nodes"
            || n.file_path.contains("/db/")
            || n.file_path.contains("/database/")
        {
            db_node_flags[idx] = true;
        }

        if n.is_file {
            let fp = n.file_path.replace('\\', "/");
            node_by_filepath.insert(fp.clone(), idx);
            filepath_entries.push((fp.clone(), idx));

            let p = Path::new(&fp);
            if let Some(stem) = p.file_stem() {
                let stem_str = stem.to_string_lossy().to_string();
                node_by_lang_and_name
                    .entry((lang, stem_str.clone()))
                    .or_insert(idx);
                node_by_name.entry(stem_str).or_insert(idx);
                if let Some(parent) = p.parent() {
                    let no_ext = parent.join(stem).to_string_lossy().replace('\\', "/");
                    let idx_path = format!("{}/index", no_ext);
                    node_by_filepath.insert(no_ext.clone(), idx);
                    filepath_entries.push((no_ext, idx));
                    node_by_filepath.insert(idx_path.clone(), idx);
                    filepath_entries.push((idx_path, idx));
                }
            }
        }

        let lang_existing = node_by_lang_and_name.get(&(lang, n.name.clone()));
        if lang_existing.is_none()
            || n.is_class
            || n.symbol_type == "component"
            || n.symbol_type == "form"
        {
            node_by_lang_and_name.insert((lang, n.name.clone()), idx);
        }

        let existing = node_by_name.get(&n.name);
        if existing.is_none()
            || n.is_class
            || n.symbol_type == "component"
            || n.symbol_type == "form"
        {
            node_by_name.insert(n.name.clone(), idx);
        }
    }

    let mut resolved_edges = Vec::with_capacity(raw_calls.len());
    let mut seen_edges: HashSet<(String, String, String)> =
        HashSet::with_capacity(raw_calls.len());

    for call in raw_calls {
        let src = &call.caller;
        let callee = &call.callee;
        if is_language_keyword_call(callee) {
            continue;
        }

        let caller_lang = node_idx_by_id
            .get(src)
            .map(|&i| lang_family_of(&nodes[i].file_path))
            .unwrap_or("other");

        let mut tgt_idx = node_idx_by_id
            .get(callee)
            .or_else(|| node_by_filepath.get(callee))
            .or_else(|| node_by_lang_and_name.get(&(caller_lang, callee.clone())))
            .or_else(|| node_by_name.get(callee))
            .copied();

        // Fuzzy match for API endpoints
        if tgt_idx.is_none()
            && (call.relation == "network"
                || callee.starts_with("/api")
                || callee.starts_with("api/"))
        {
            let clean_ep = callee.trim_start_matches('/');
            for (fp, idx) in &filepath_entries {
                if fp.contains(clean_ep) {
                    tgt_idx = Some(*idx);
                    break;
                }
            }
        }

        // Materialize dynamic API endpoint node for unresolved network calls
        if tgt_idx.is_none()
            && call.relation == "network"
            && callee.len() > 1
            && !callee.contains('{')
        {
            let ep_id = format!("api::{}", callee);
            let ep_name = format!("🌐 {}", callee);
            let mut ep_bubble = SymbolBubble::new(
                ep_id.clone(),
                ep_name,
                callee.clone(),
                1,
                SymbolKind::FormOrEndpoint,
                "server".to_string(),
                "action".to_string(),
            );
            ep_bubble.folder = "api".to_string();
            ep_bubble.stereotype = "«API Endpoint»".to_string();
            ep_bubble.symbol_type = "endpoint".to_string();
            ep_bubble.docstring = format!("Point d'accès réseau : {}", callee);
            let new_idx = nodes.len();
            nodes.push(ep_bubble);
            db_node_flags.push(false);
            node_idx_by_id.insert(callee.clone(), new_idx);
            node_idx_by_id.insert(ep_id, new_idx);
            tgt_idx = Some(new_idx);
        }

        if let Some(target_idx) = tgt_idx {
            let target_id = nodes[target_idx].id.clone();
            if target_id != *src {
                let key = (src.clone(), target_id.clone(), call.relation.clone());
                if seen_edges.insert(key) {
                    let is_db_target = db_node_flags.get(target_idx).copied().unwrap_or(false);
                    let (edge_type, mut filters) = match call.relation.as_str() {
                        "contains" => (EdgeType::Contains, FilterAffiliation::PHYSICAL),
                        "imports" => (EdgeType::Import, FilterAffiliation::PHYSICAL),
                        "calls" => (
                            EdgeType::Call,
                            FilterAffiliation::PHYSICAL | FilterAffiliation::SEMANTIC,
                        ),
                        "renders" => (
                            EdgeType::Render,
                            FilterAffiliation::PHYSICAL | FilterAffiliation::SEMANTIC,
                        ),
                        "inherits" => (
                            EdgeType::Inherit,
                            FilterAffiliation::PHYSICAL | FilterAffiliation::SEMANTIC,
                        ),
                        "network" => (
                            EdgeType::Network,
                            FilterAffiliation::NETWORK_RPC | FilterAffiliation::PHYSICAL,
                        ),
                        "submits" => (
                            EdgeType::NetworkRPC,
                            FilterAffiliation::NETWORK_RPC | FilterAffiliation::PHYSICAL,
                        ),
                        "documents" => (EdgeType::Documents, FilterAffiliation::SEMANTIC),
                        "queries" => (
                            EdgeType::DatabaseQuery,
                            FilterAffiliation::DATABASE_QUERY | FilterAffiliation::PHYSICAL,
                        ),
                        _ => {
                            if is_db_target {
                                (
                                    EdgeType::DatabaseQuery,
                                    FilterAffiliation::DATABASE_QUERY | FilterAffiliation::PHYSICAL,
                                )
                            } else {
                                (EdgeType::Call, FilterAffiliation::PHYSICAL)
                            }
                        }
                    };

                    // Detect cross-galaxy illegal import (e.g. client importing server directly)
                    let mut violation_reason = None;
                    if call.relation == "imports" {
                        if let Some(&src_idx) = node_idx_by_id.get(src) {
                            let s_gal = nodes[src_idx].galaxy.as_str();
                            let t_gal = nodes[target_idx].galaxy.as_str();
                            if (s_gal == "client" && (t_gal == "server" || t_gal == "data-nodes"))
                                || (s_gal == "contracts" && (t_gal == "client" || t_gal == "server"))
                            {
                                filters |= FilterAffiliation::SECURITY_VIOLATES;
                                let reason = format!(
                                    "[CROSS_GALAXY_VIOLATION] Import inter-galaxie illégal: '{}' ({}) -> '{}' ({})",
                                    src, s_gal, target_id, t_gal
                                );
                                violation_reason = Some(reason.clone());
                                let src_node = &mut nodes[src_idx];
                                src_node.has_security_violation = true;
                                src_node.metadata.violations.push(reason);
                            }
                        }
                    }

                    let mut edge =
                        AffiliationEdge::new(src.clone(), target_id, edge_type, filters);
                    edge.violation_details = violation_reason;
                    edge.order_label = if call.order_label.is_empty() {
                        format!("{}.", resolved_edges.len() + 1)
                    } else {
                        call.order_label.clone()
                    };
                    resolved_edges.push(edge);
                }
            }
        }
    }

    // Compute in_degree, out_degree, and DAG stage_idx using usize-indexed vectors (0 String allocations)
    let mut in_degrees = vec![0usize; nodes.len()];
    let mut out_degrees = vec![0usize; nodes.len()];
    for e in &resolved_edges {
        if let Some(&t_idx) = node_idx_by_id.get(&e.target) {
            in_degrees[t_idx] += 1;
        }
        if let Some(&s_idx) = node_idx_by_id.get(&e.source) {
            out_degrees[s_idx] += 1;
        }
    }

    for (idx, n) in nodes.iter_mut().enumerate() {
        n.in_degree = in_degrees[idx];
        n.out_degree = out_degrees[idx];

        if n.in_degree == 0 && n.out_degree > 0 {
            n.stage_idx = 0; // Entrypoint
        } else if n.out_degree > 0 && n.in_degree > 0 {
            n.stage_idx = 1; // Coordinator
        } else if n.layer == "database"
            || security_linter::lexer::contains_ascii_case_insensitive(&n.name, "model")
        {
            n.stage_idx = 3; // Persistence
        } else {
            n.stage_idx = 2; // Processing
        }
    }

    resolved_edges
}

std::thread_local! {
    static ACTIVE_LINE_STARTS: std::cell::RefCell<Option<(usize, usize, Vec<usize>)>> =
        const { std::cell::RefCell::new(None) };
}

fn set_active_line_index(content: &str) {
    let mut starts = Vec::with_capacity(content.len() / 32 + 2);
    starts.push(0);
    for (idx, b) in content.bytes().enumerate() {
        if b == b'\n' {
            starts.push(idx + 1);
        }
    }
    ACTIVE_LINE_STARTS.with(|cell| {
        *cell.borrow_mut() = Some((content.as_ptr() as usize, content.len(), starts));
    });
}

pub(crate) fn line_number_at(content: &str, byte_offset: usize) -> usize {
    let end = byte_offset.min(content.len());
    let ptr = content.as_ptr() as usize;
    let fast = ACTIVE_LINE_STARTS.with(|cell| {
        let borrow = cell.borrow();
        if let Some((cached_ptr, cached_len, ref starts)) = *borrow {
            if ptr == cached_ptr && end <= cached_len {
                return Some(starts.partition_point(|&s| s <= end));
            }
        }
        None
    });
    if let Some(line) = fast {
        return line.max(1);
    }
    set_active_line_index(content);
    ACTIVE_LINE_STARTS
        .with(|cell| {
            cell.borrow()
                .as_ref()
                .map(|(_, _, starts)| starts.partition_point(|&s| s <= end))
        })
        .unwrap_or(1)
        .max(1)
}

pub(crate) fn normalize_path(path_str: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path_str.split('/') {
        if seg == "." || seg.is_empty() {
            continue;
        } else if seg == ".." {
            parts.pop();
        } else {
            parts.push(seg);
        }
    }
    parts.join("/")
}

pub(crate) fn safe_slice(s: &str, start: usize, len: usize) -> &str {
    if start >= s.len() {
        return "";
    }
    let actual_start = if s.is_char_boundary(start) {
        start
    } else {
        (0..start)
            .rev()
            .find(|&i| s.is_char_boundary(i))
            .unwrap_or(0)
    };
    let target_end = (actual_start + len).min(s.len());
    let actual_end = if s.is_char_boundary(target_end) {
        target_end
    } else {
        (actual_start..target_end)
            .rev()
            .find(|&i| s.is_char_boundary(i))
            .unwrap_or(actual_start)
    };
    &s[actual_start..actual_end]
}

pub(crate) fn extract_fn_body_slice(s: &str, start: usize, max_len: usize) -> &str {
    let window = safe_slice(s, start, max_len);
    let mut depth: i32 = 0;
    let mut opened = false;
    for (idx, b) in window.bytes().enumerate() {
        if !opened && b == b';' {
            return &window[..idx];
        }
        if b == b'{' {
            depth += 1;
            opened = true;
        } else if b == b'}' && opened {
            depth -= 1;
            if depth <= 0 {
                let end = (idx + 1).min(window.len());
                if window.is_char_boundary(end) {
                    return &window[..end];
                }
                break;
            }
        }
    }
    window
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::{analyze_java, analyze_php, analyze_rust};

    #[test]
    fn test_php_analysis() {
        let php_code = r#"<?php
namespace App\Controller;

use App\Service\PaymentGateway;
use App\Model\User;

class UserController extends BaseController implements UserInterface {
    public function getProfile($userId) {
        $user = $this->findUser($userId);
        return $user;
    }
}
"#;
        let res = analyze_php("server/controllers/UserController.php", php_code);
        assert!(res.nodes.iter().any(|n| n.is_file && n.name == "UserController.php"));
        assert_eq!(res.nodes[0].metadata.file_type, "php");
        let cls = res.nodes.iter().find(|n| n.name == "UserController").expect("UserController class");
        assert!(cls.is_class);
        assert!(res.calls.iter().any(|c| c.relation == "imports" && c.callee == "PaymentGateway"));
        assert!(res.calls.iter().any(|c| c.relation == "inherits" && c.callee == "BaseController"));
        assert!(res.nodes.iter().any(|n| n.name == "getProfile"));
    }

    #[test]
    fn test_java_analysis() {
        let java_code = r#"
package com.aether.minecraft.plugin;

import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.event.Listener;
import org.bukkit.event.EventHandler;
import org.bukkit.event.player.PlayerJoinEvent;

public class AetherPaperPlugin extends JavaPlugin implements Listener {
    private String serverName;
    private int maxPlayers;

    @Override
    public void onEnable() {
        registerEvents();
        getLogger().info("Aether Plugin Enabled!");
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        handleJoin(event);
    }

    private void handleJoin(PlayerJoinEvent event) {
    }
}
"#;
        let res = analyze_java("plugins/AetherPaperPlugin.java", java_code);
        assert!(res.nodes.iter().any(|n| n.is_file && n.name == "AetherPaperPlugin.java"));
        assert_eq!(res.nodes[0].metadata.file_type, "java");
        let cls = res.nodes.iter().find(|n| n.name == "AetherPaperPlugin").expect("class found");
        assert!(cls.is_class);
        assert_eq!(cls.stereotype, "«Plugin»");
        assert!(res.calls.iter().any(|c| c.relation == "imports" && c.callee == "JavaPlugin"));
        assert!(res.calls.iter().any(|c| c.relation == "inherits" && c.callee == "JavaPlugin"));
        assert!(res.calls.iter().any(|c| c.relation == "inherits" && c.callee == "Listener"));
        let evt = res.nodes.iter().find(|n| n.name == "onPlayerJoin").expect("event method");
        assert_eq!(evt.stereotype, "«Event Listener»");
        assert!(res.calls.iter().any(|c| c.relation == "calls" && c.callee == "handleJoin"));
    }
    #[test]
    fn test_rust_and_markdown_analysis() {
        let rs_code = r#"
pub struct BookingService {
    pub db_url: String,
    pub max_retries: u32,
}

pub fn compute_price(nights: u32) -> u64 {
    validate_nights(nights);
    nights as u64 * 100
}

pub fn validate_nights(n: u32) -> bool {
    n > 0
}
"#;
        let res = analyze_rust("server/domain/booking.rs", rs_code);
        assert!(res.nodes.iter().any(|n| n.is_file && n.name == "booking.rs"));
        let st = res
            .nodes
            .iter()
            .find(|n| n.name == "BookingService")
            .expect("BookingService struct");
        assert!(st.is_class);
        assert_eq!(st.metadata.attributes.len(), 2);
        assert!(res
            .calls
            .iter()
            .any(|c| c.relation == "contains" && c.callee.ends_with("BookingService")));
        assert!(res
            .calls
            .iter()
            .any(|c| c.relation == "calls" && c.callee == "validate_nights"));
    }

    #[test]
    fn test_scanner_with_exclusions() {
        let temp_dir = std::env::temp_dir().join(format!("aether_test_excl_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()));
        let src_dir = temp_dir.join("src");
        let tests_dir = temp_dir.join("tests");
        let mocks_dir = temp_dir.join("mocks");
        let _ = std::fs::create_dir_all(&src_dir);
        let _ = std::fs::create_dir_all(&tests_dir);
        let _ = std::fs::create_dir_all(&mocks_dir);

        let _ = std::fs::write(src_dir.join("main.rs"), "pub fn main() {}");
        let _ = std::fs::write(src_dir.join("ui.spec.ts"), "export const a = 1;");
        let _ = std::fs::write(tests_dir.join("integration.rs"), "pub fn test_run() {}");
        let _ = std::fs::write(mocks_dir.join("db.rs"), "pub fn mock_db() {}");

        let scanner = ProjectScanner::default();
        let exclusions = vec!["tests".to_string(), "*.spec.*".to_string(), "mocks".to_string()];
        let graph = scanner.scan_project_with_exclusions(&temp_dir, &exclusions);

        let found_files: Vec<String> = graph.nodes.iter().filter(|n| n.is_file).map(|n| n.name.clone()).collect();
        assert!(found_files.contains(&"main.rs".to_string()), "main.rs should be scanned");
        assert!(!found_files.contains(&"ui.spec.ts".to_string()), "ui.spec.ts should be excluded");
        assert!(!found_files.contains(&"integration.rs".to_string()), "integration.rs should be excluded");
        assert!(!found_files.contains(&"db.rs".to_string()), "db.rs should be excluded");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_scanner_contract_structure_rules_reach_graph() {
        let temp_dir = std::env::temp_dir().join(format!("aether_test_structure_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()));
        let svc = temp_dir.join("svc");
        let _ = std::fs::create_dir_all(&svc);
        let _ = std::fs::write(
            svc.join("README.md"),
            "---\nid: svc\nlayer: domain\nforbidden_functions: [\"unwrap\"]\nforbidden_extensions: [\"exe\"]\nmax_files_per_folder: 3\n---\n# Svc\n",
        );
        let _ = std::fs::write(svc.join("a.rs"), "pub fn run(o: Option<i32>) -> i32 {\n    o.unwrap()\n}\n");
        let _ = std::fs::write(svc.join("b.rs"), "pub fn b() {}\n");
        let _ = std::fs::write(svc.join("c.rs"), "pub fn c() {}\n");
        let _ = std::fs::write(svc.join("d.rs"), "pub fn d() {}\n");
        let _ = std::fs::write(svc.join("blob.exe"), "MZ");

        let graph = ProjectScanner::default().scan_project(&temp_dir);
        let rules_of = |file: &str| -> Vec<String> {
            graph
                .nodes
                .iter()
                .filter(|n| n.file_path == file)
                .flat_map(|n| n.metadata.cve_anomalies.iter().map(|a| a.rule_id.clone()))
                .collect()
        };

        assert!(rules_of("svc/a.rs").contains(&"RULE_FORBIDDEN_FUNCTION".to_string()), "forbidden function must be flagged on the code node");
        let readme_rules = rules_of("svc/README.md");
        assert!(readme_rules.contains(&"RULE_FORBIDDEN_EXTENSION".to_string()), "non-scanned .exe must be reported on the contract README: {:?}", readme_rules);
        assert!(readme_rules.contains(&"RULE_MAX_FILES".to_string()), "too many files must be reported on the contract README: {:?}", readme_rules);
        assert!(!rules_of("svc/b.rs").iter().any(|r| r.starts_with("RULE_FORBIDDEN_") || r == "RULE_MAX_FILES"));

        let a_node = graph.nodes.iter().find(|n| n.file_path == "svc/a.rs" && n.is_file).unwrap();
        assert!(a_node.has_security_violation, "forbidden function is a blocking violation");
        let readme_node = graph.nodes.iter().find(|n| n.file_path == "svc/README.md" && n.is_file).unwrap();
        assert!(readme_node.has_security_violation, "forbidden extension marks the README as violated");
        assert!(
            graph.edges.iter().any(|e| e.violation_details.as_deref().is_some_and(|d| d.contains("RULE_MAX_FILES"))),
            "a warning edge must exist for RULE_MAX_FILES"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_scanner_evaluates_plugins_from_aether_directory() {
        let temp_dir = std::env::temp_dir().join(format!("aether_test_plugins_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()));
        let src_dir = temp_dir.join("src");
        let _ = std::fs::create_dir_all(&src_dir);

        let vuln_py = r#"
def fetch_user_data(cursor, user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
"#;
        let _ = std::fs::write(src_dir.join("service.py"), vuln_py);

        // Before plugins are installed: scan runs normally
        let scanner = ProjectScanner::default();
        let graph_before = scanner.scan_project_with_exclusions(&temp_dir, &[]);
        let had_sqli_before = graph_before.nodes.iter().any(|n| {
            n.metadata.cve_anomalies.iter().any(|a| a.rule_id == "semgrep-owasp-sqli-format")
        });
        assert!(!had_sqli_before, "Community plugin rule should not be active before unpacking");

        // Hydrate community bundle into .aether/plugins
        let plugins_dir = temp_dir.join(".aether").join("plugins");
        let unpacked = security_linter::CommunityBundle::unpack_to_directory(&plugins_dir)
            .expect("Unpack community bundle should succeed");
        assert!(unpacked.exists());

        // After plugins are installed: scanner must detect the plugin violation!
        let graph_after = scanner.scan_project_with_exclusions(&temp_dir, &[]);
        let found_sqli = graph_after.nodes.iter().any(|n| {
            n.metadata.cve_anomalies.iter().any(|a| a.rule_id == "semgrep-owasp-sqli-format")
        });
        assert!(found_sqli, "ProjectScanner must evaluate rules from .aether/plugins and attach anomalies");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_zig_ast_analysis() {
        let zig_code = r#"
const std = @import("std");
const socket = @import("network/socket.zig");

pub const ServerConfig = struct {
    port: u16 = 8080,
    host: []const u8,
};

pub fn initializeServer(allocator: std.mem.Allocator, port: u16) !ServerConfig {
    validatePort(port);
    return ServerConfig{ .port = port, .host = "127.0.0.1" };
}

pub fn handleClient(self: *ServerConfig, stream: std.net.Stream) void {
    processStream(stream);
}

fn validatePort(port: u16) bool {
    return port > 0;
}

test "test initializeServer" {
    const cfg = ServerConfig{ .port = 8080, .host = "127.0.0.1" };
    try std.testing.expect(cfg.port == 8080);
}
"#;
        let res = analyze_zig("src/server/core.zig", zig_code);

        // 1. File bubble
        assert!(res.nodes.iter().any(|n| n.is_file && n.name == "core.zig"));
        assert_eq!(res.nodes[0].metadata.file_type, "zig");

        // 2. Import bubble and call edges
        assert!(res.calls.iter().any(|c| c.relation == "imports" && c.callee == "std"));
        assert!(res.calls.iter().any(|c| c.relation == "imports" && c.callee == "network/socket.zig"));
        assert!(res.nodes.iter().any(|n| n.name == "std" && n.stereotype == "«Import»"));

        // 3. Struct bubble and fields
        let st = res.nodes.iter().find(|n| n.name == "ServerConfig").expect("ServerConfig struct");
        assert!(st.is_class);
        assert_eq!(st.metadata.attributes.len(), 2);
        assert!(st.metadata.attributes.iter().any(|a| a.name == "port"));
        assert!(st.metadata.attributes.iter().any(|a| a.name == "host"));

        // 4. Function bubble and call edge
        let init_fn = res.nodes.iter().find(|n| n.name == "initializeServer").expect("initializeServer function");
        assert!(!init_fn.is_class);
        assert!(res.calls.iter().any(|c| c.caller.ends_with("initializeServer") && c.callee == "validatePort"));

        // 5. Method bubble with self parameter
        let method = res.nodes.iter().find(|n| n.name == "handleClient").expect("handleClient method");
        assert_eq!(method.stereotype, "«Method»");
        assert!(res.calls.iter().any(|c| c.caller.ends_with("handleClient") && c.callee == "processStream"));

        // 6. Inline test stripping verification
        assert!(!res.nodes.iter().any(|n| n.name.contains("test initializeServer")));

        // 7. Symbol helper function verification
        let symbols = analyze_zig_symbols(Path::new("src/server/core.zig"), zig_code);
        assert!(symbols.iter().any(|s| s.name == "ServerConfig"));
        assert!(symbols.iter().any(|s| s.name == "initializeServer"));
    }

    #[test]
    fn test_csharp_ast_analysis() {
        let cs_code = r#"
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace MyCompany.Orders.Controllers;

[ApiController]
[Route("api/[controller]")]
public class OrderController : ControllerBase {
    public int MaxRetries { get; set; } = 3;
    public string OrderId { get; init; }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetOrder(int id) {
        ValidateId(id);
        return Ok(id);
    }

    [HttpPost]
    public async Task<IActionResult> CreateOrder(string payload) {
        return Ok();
    }

    private void ValidateId(int id) {
    }
}
"#;
        let res = analyze_csharp("src/Controllers/OrderController.cs", cs_code);

        // 1. File bubble
        assert!(res.nodes.iter().any(|n| n.is_file && n.name == "OrderController.cs"));
        assert_eq!(res.nodes[0].metadata.file_type, "csharp");

        // 2. Usings
        assert!(res.calls.iter().any(|c| c.relation == "imports" && c.callee == "System"));
        assert!(res.calls.iter().any(|c| c.relation == "imports" && c.callee == "Microsoft.AspNetCore.Mvc"));

        // 3. Namespace bubble
        let ns = res.nodes.iter().find(|n| n.name == "MyCompany.Orders.Controllers").expect("namespace bubble");
        assert_eq!(ns.stereotype, "«Namespace»");

        // 4. Class bubble & inheritance
        let cls = res.nodes.iter().find(|n| n.name == "OrderController").expect("OrderController class");
        assert!(cls.is_class);
        assert_eq!(cls.stereotype, "«Controller»");
        assert!(res.calls.iter().any(|c| c.relation == "inherits" && c.callee == "ControllerBase"));

        // 5. Property bubbles and attributes
        assert!(cls.metadata.attributes.iter().any(|a| a.name == "MaxRetries"));
        assert!(cls.metadata.attributes.iter().any(|a| a.name == "OrderId"));
        assert!(res.nodes.iter().any(|n| n.name == "MaxRetries" && n.stereotype == "«Property»"));
        assert!(res.nodes.iter().any(|n| n.name == "OrderId" && n.stereotype == "«Property»"));

        // 6. Method & Route attribute
        let get_method = res.nodes.iter().find(|n| n.name == "GetOrder").expect("GetOrder method");
        assert_eq!(get_method.kind, SymbolKind::FormOrEndpoint);
        assert_eq!(get_method.stereotype, "«Endpoint»");
        assert!(res.routes_declared.iter().any(|(r, _)| r.contains("HttpGet")));
        assert!(res.calls.iter().any(|c| c.caller.ends_with("GetOrder") && c.callee == "ValidateId"));

        // 7. Symbol helper function verification
        let symbols = analyze_csharp_symbols(Path::new("src/Controllers/OrderController.cs"), cs_code);
        assert!(symbols.iter().any(|s| s.name == "OrderController"));
        assert!(symbols.iter().any(|s| s.name == "GetOrder"));
    }

    #[test]
    fn test_svelte_scanning_cross_lang_isolation_extern_fn_and_cache_gc() {
        let temp_dir = std::env::temp_dir().join(format!(
            "aether_test_wave2_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let rs_dir = temp_dir.join("crates/core");
        let ui_dir = temp_dir.join("ui/src");
        let _ = std::fs::create_dir_all(&rs_dir);
        let _ = std::fs::create_dir_all(&ui_dir);

        // 1. Rust file with extern fn followed by main() and use SymbolBubble
        let rs_models = "pub struct SymbolBubble { pub id: String }\n";
        let rs_main = r#"
use crate::models::SymbolBubble;
extern "system" {
    fn AttachConsole(dw_process_id: u32) -> i32;
}
fn main() {
    real_main();
}
fn real_main() {}
"#;
        let _ = std::fs::write(rs_dir.join("models.rs"), rs_models);
        let _ = std::fs::write(rs_dir.join("main.rs"), rs_main);

        // 2. TypeScript file defining an identically-named SymbolBubble interface + Svelte components
        let ts_types = "export interface SymbolBubble { id: string; }\n";
        let svelte_child = "<script lang=\"ts\">\nexport function openChild() {}\n</script>\n<div>Header</div>\n";
        let svelte_app = "<script lang=\"ts\">\nimport HeaderDeck from './HeaderDeck.svelte';\n</script>\n<HeaderDeck />\n";
        let _ = std::fs::write(ui_dir.join("graph.ts"), ts_types);
        let _ = std::fs::write(ui_dir.join("HeaderDeck.svelte"), svelte_child);
        let _ = std::fs::write(ui_dir.join("App.svelte"), svelte_app);

        // Seed a stale orphan cache file in .aether/cache/ast/
        let cache_dir = temp_dir.join(".aether/cache/ast");
        let _ = std::fs::create_dir_all(&cache_dir);
        let stale_cache = cache_dir.join("deadbeef00000000stale.json");
        let _ = std::fs::write(&stale_cache, "{}");
        assert!(stale_cache.exists());

        let scanner = ProjectScanner::default();
        let graph = scanner.scan_project(&temp_dir);

        // Verify stale cache entry was garbage-collected
        assert!(
            !stale_cache.exists(),
            "Stale AST cache entry must be removed after full project scan"
        );

        // Verify .svelte files are scanned and App.svelte renders HeaderDeck.svelte
        assert!(
            graph.nodes.iter().any(|n| n.is_file && n.name == "App.svelte"),
            "App.svelte must be present in the AST graph"
        );
        assert!(
            graph.edges.iter().any(|e| {
                e.source == "file::ui/src/App.svelte"
                    && e.target == "file::ui/src/HeaderDeck.svelte"
            }),
            "App.svelte must have an import/render edge to HeaderDeck.svelte"
        );

        // Verify Rust `use SymbolBubble` resolves to Rust `crates/core/models.rs::SymbolBubble`, NOT TypeScript `ui/src/graph.ts::SymbolBubble`
        assert!(
            graph.edges.iter().any(|e| {
                e.source == "file::crates/core/main.rs"
                    && e.target == "crates/core/models.rs::SymbolBubble"
            }),
            "Rust use SymbolBubble must resolve to Rust struct, not TypeScript interface"
        );
        assert!(
            !graph.edges.iter().any(|e| {
                e.source == "file::crates/core/main.rs"
                    && e.target == "ui/src/graph.ts::SymbolBubble"
            }),
            "Rust file must NOT link to TypeScript SymbolBubble"
        );

        // Verify extern fn AttachConsole does NOT swallow fn main() body and call real_main
        assert!(
            !graph.edges.iter().any(|e| {
                e.source.ends_with("::AttachConsole") && e.target.ends_with("::real_main")
            }),
            "extern fn AttachConsole must not bleed into main() and claim to call real_main"
        );
        assert!(
            graph.edges.iter().any(|e| {
                e.source.ends_with("::main") && e.target.ends_with("::real_main")
            }),
            "fn main() must call real_main()"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
