use crate::api_routes::AppState;
use crate::extract_live_audit_from_graph;
use ai_file_bridge::AuditWriter;
use ast_scanner::ProjectScanner;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use core_graph::dataflow::{SanitizerRule, TaintSinkRule, TaintSourceRule};
use security_linter::plugin::{
    MatchMode, PluginEngine, PluginManifest, PluginRule, PrecededWindowCondition, RuleConditions,
    RuleTestCase,
};
use security_linter::semgrep_importer::SemgrepImporter;
use security_linter::{CommunityBundle, SecretGuard};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
pub struct PluginRuleSummary {
    pub id: String,
    pub cwe_id: String,
    pub name: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
    pub file_extensions: Vec<String>,
    pub match_mode: String,
    pub check_literals: bool,
    pub must_contain: Vec<String>,
    pub must_not_contain: Vec<String>,
    pub regex_patterns: Vec<String>,
    pub forbidden_tokens: Vec<String>,
    pub not_preceded_within_lines: Option<PrecededWindowCondition>,
    pub in_path_matching: Vec<String>,
    pub not_in_path_matching: Vec<String>,
    pub ast_scope: Option<String>,
    pub test_cases_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginEntryInfo {
    pub name: String,
    pub rel_path: String,
    pub folder_alias: Option<String>,
    pub version: String,
    pub author: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub profile: Option<String>,
    pub tags: Vec<String>,
    pub rules_count: usize,
    pub test_cases_count: usize,
    pub taint_sources_count: usize,
    pub taint_sinks_count: usize,
    pub sanitizers_count: usize,
    pub rules: Vec<PluginRuleSummary>,
    pub taint_sources: Vec<TaintSourceRule>,
    pub taint_sinks: Vec<TaintSinkRule>,
    pub sanitizers: Vec<SanitizerRule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginsInventoryResponse {
    pub status: String,
    pub plugins_dir: String,
    pub community_bundle_installed: bool,
    pub community_bundle_rules_count: usize,
    pub total_plugins: usize,
    pub enabled_plugins: usize,
    pub total_active_rules: usize,
    pub total_taint_sources: usize,
    pub total_taint_sinks: usize,
    pub total_sanitizers: usize,
    pub plugins: Vec<PluginEntryInfo>,
}

#[derive(Debug, Deserialize)]
pub struct TogglePluginRequest {
    pub rel_path: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct TestPluginsRequest {
    #[serde(default)]
    pub rel_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImportSemgrepRequest {
    pub plugin_name: String,
    pub yaml_content: String,
}

#[derive(Debug, Deserialize)]
pub struct DeletePluginRequest {
    pub rel_path: String,
}

#[derive(Debug, Deserialize)]
pub struct UpsertPluginRuleRequest {
    pub plugin_name: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub plugin_description: Option<String>,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub cwe_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub file_extensions: Vec<String>,
    #[serde(default)]
    pub match_mode: Option<String>,
    #[serde(default)]
    pub must_contain: Vec<String>,
    #[serde(default)]
    pub must_not_contain: Vec<String>,
    #[serde(default)]
    pub regex_patterns: Vec<String>,
    #[serde(default)]
    pub forbidden_tokens: Vec<String>,
    #[serde(default)]
    pub check_literals: bool,
    #[serde(default)]
    pub not_preceded_within_lines: Option<PrecededWindowCondition>,
    #[serde(default)]
    pub in_path_matching: Vec<String>,
    #[serde(default)]
    pub not_in_path_matching: Vec<String>,
    #[serde(default)]
    pub ast_scope: Option<String>,
    #[serde(default)]
    pub test_cases: Vec<RuleTestCase>,
    #[serde(default)]
    pub taint_sources: Option<Vec<TaintSourceRule>>,
    #[serde(default)]
    pub taint_sinks: Option<Vec<TaintSinkRule>>,
    #[serde(default)]
    pub sanitizers: Option<Vec<SanitizerRule>>,
}

fn default_severity() -> String {
    "HIGH".to_string()
}

/// Validates and sanitizes a plugin directory slug so it can never escape `.aether/plugins/`.
pub fn sanitize_plugin_slug(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Plugin name cannot be empty".to_string());
    }
    if trimmed.len() > 64 {
        return Err("Plugin name is too long (max 64 characters)".to_string());
    }
    if trimmed.contains('\0')
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains(':')
        || trimmed == "."
    {
        return Err(format!(
            "Invalid plugin name '{}': path separators or traversal tokens are forbidden",
            trimmed
        ));
    }
    let mut slug = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            slug.push(ch.to_ascii_lowercase());
        } else if ch == ' ' {
            slug.push('-');
        } else {
            return Err(format!(
                "Invalid character '{}' in plugin name '{}': use letters, digits, '-' or '_'",
                ch, trimmed
            ));
        }
    }
    let slug = slug.trim_matches(|c| c == '-' || c == '_').to_string();
    if slug.is_empty() {
        return Err("Plugin name must contain at least one alphanumeric character".to_string());
    }
    Ok(slug)
}

fn push_normal_rel_path(base: &Path, rel: &str) -> Result<PathBuf, String> {
    if rel.is_empty() || rel.contains('\0') {
        return Err("Empty or invalid relative path".to_string());
    }
    let normalized = rel.replace('\\', "/");
    if normalized.starts_with('/') || normalized.starts_with("//") || normalized.contains(':') {
        return Err("Absolute paths, UNC paths, and drive letters are forbidden".to_string());
    }
    let candidate = Path::new(&normalized);
    if candidate.is_absolute() || candidate.has_root() {
        return Err("Absolute paths are forbidden".to_string());
    }
    let mut out = base.to_path_buf();
    let mut normal_count = 0usize;
    for comp in candidate.components() {
        match comp {
            Component::Normal(seg) => {
                out.push(seg);
                normal_count += 1;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("Path traversal or root component forbidden".to_string());
            }
        }
    }
    if normal_count == 0 {
        return Err("Relative path must specify a file inside .aether/plugins".to_string());
    }
    Ok(out)
}

fn is_allowed_plugin_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .map(|e| matches!(e.to_ascii_lowercase().as_str(), "yaml" | "yml" | "json"))
        .unwrap_or(false)
}

/// Strictly confines a plugin manifest path inside `<project_root>/.aether/plugins`.
pub fn resolve_confined_plugin_file(
    project_root: &Path,
    rel_path: &str,
) -> Result<PathBuf, (StatusCode, Json<Value>)> {
    let plugins_dir = project_root.join(".aether").join("plugins");
    if !plugins_dir.is_dir() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": "Plugins directory .aether/plugins does not exist" })),
        ));
    }
    let candidate = push_normal_rel_path(&plugins_dir, rel_path).map_err(|msg| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg })),
        )
    })?;
    if !is_allowed_plugin_extension(&candidate) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Only .yaml, .yml, and .json plugin manifests are allowed" })),
        ));
    }
    if SecretGuard::is_secret_path(&candidate) || SecretGuard::is_secret_path(rel_path) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Secret file access prohibited" })),
        ));
    }
    let canon_plugins = fs::canonicalize(&plugins_dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Cannot canonicalize plugins dir: {e}") })),
        )
    })?;
    let canon_target = fs::canonicalize(&candidate).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": format!("Plugin file '{}' not found", rel_path) })),
        )
    })?;
    if !canon_target.starts_with(&canon_plugins) || !canon_target.is_file() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Plugin path escapes .aether/plugins boundary" })),
        ));
    }
    Ok(canon_target)
}

fn parse_manifest_str(content: &str) -> Result<PluginManifest, String> {
    match serde_yaml::from_str::<PluginManifest>(content) {
        Ok(m) => Ok(m),
        Err(yaml_err) => serde_json::from_str::<PluginManifest>(content)
            .map_err(|json_err| format!("YAML error: {yaml_err}; JSON error: {json_err}")),
    }
}

fn collect_plugin_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = fs::read_dir(dir) {
        let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                if p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case("visuals"))
                {
                    continue;
                }
                collect_plugin_files(&p, out);
            } else if p.is_file() && is_allowed_plugin_extension(&p) {
                if p.file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case("visual-plugin"))
                {
                    continue;
                }
                out.push(p);
            }
        }
    }
}

/// Builds a complete inventory of all YAML/JSON plugins (both enabled and disabled) under `.aether/plugins`.
pub fn build_plugins_inventory(project_root: &Path) -> PluginsInventoryResponse {
    let plugins_dir = project_root.join(".aether").join("plugins");
    let community_bundle_rules_count = CommunityBundle::load_embedded_manifest()
        .map(|m| m.rules.len())
        .unwrap_or(24);
    let community_bundle_installed = plugins_dir.join("community").join("plugin.yaml").is_file();

    let mut files = Vec::new();
    if plugins_dir.is_dir() {
        collect_plugin_files(&plugins_dir, &mut files);
    }

    let mut plugins = Vec::new();
    let mut enabled_plugins = 0usize;
    let mut total_active_rules = 0usize;
    let mut total_taint_sources = 0usize;
    let mut total_taint_sinks = 0usize;
    let mut total_sanitizers = 0usize;

    for file in files {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        let Ok(manifest) = parse_manifest_str(&content) else {
            continue;
        };
        let rel_path = file
            .strip_prefix(&plugins_dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let folder_alias = file
            .parent()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().to_string());

        let test_cases_count: usize = manifest.rules.iter().map(|r| r.test_cases.len()).sum();

        if manifest.enabled {
            enabled_plugins += 1;
            total_active_rules += manifest.rules.len();
            total_taint_sources += manifest.taint_sources.len();
            total_taint_sinks += manifest.taint_sinks.len();
            total_sanitizers += manifest.sanitizers.len();
        }

        let rules = manifest
            .rules
            .iter()
            .map(|r| PluginRuleSummary {
                id: r.id.clone(),
                cwe_id: r.cwe_id.clone(),
                name: r.name.clone(),
                category: r.category.clone(),
                severity: r.severity.clone(),
                description: r.description.clone(),
                remediation: r.remediation.clone(),
                file_extensions: r.file_extensions.clone(),
                match_mode: match r.match_mode {
                    MatchMode::WholeFile => "whole_file".to_string(),
                    MatchMode::LineByLine => "line_by_line".to_string(),
                },
                check_literals: r.conditions.check_literals,
                must_contain: r.conditions.must_contain.clone(),
                must_not_contain: r.conditions.must_not_contain.clone(),
                regex_patterns: r.conditions.regex_patterns.clone(),
                forbidden_tokens: r.conditions.forbidden_tokens.clone(),
                not_preceded_within_lines: r.conditions.not_preceded_within_lines.clone(),
                in_path_matching: r.conditions.in_path_matching.clone(),
                not_in_path_matching: r.conditions.not_in_path_matching.clone(),
                ast_scope: r.conditions.ast_scope.clone(),
                test_cases_count: r.test_cases.len(),
            })
            .collect();

        plugins.push(PluginEntryInfo {
            name: manifest.name,
            rel_path,
            folder_alias,
            version: manifest.version,
            author: manifest.author,
            description: manifest.description,
            enabled: manifest.enabled,
            profile: manifest.profile,
            tags: manifest.tags,
            rules_count: manifest.rules.len(),
            test_cases_count,
            taint_sources_count: manifest.taint_sources.len(),
            taint_sinks_count: manifest.taint_sinks.len(),
            sanitizers_count: manifest.sanitizers.len(),
            rules,
            taint_sources: manifest.taint_sources,
            taint_sinks: manifest.taint_sinks,
            sanitizers: manifest.sanitizers,
        });
    }

    PluginsInventoryResponse {
        status: "ok".to_string(),
        plugins_dir: plugins_dir.to_string_lossy().to_string(),
        community_bundle_installed,
        community_bundle_rules_count,
        total_plugins: plugins.len(),
        enabled_plugins,
        total_active_rules,
        total_taint_sources,
        total_taint_sinks,
        total_sanitizers,
        plugins,
    }
}

/// Rescans the active code graph after any plugin mutation so the Cockpit updates live.
async fn rescan_after_plugin_mutation(state: &AppState) -> (usize, usize) {
    let p_root = state.project_root.read().await.clone();
    let excl = state.custom_exclusions.read().await.clone();
    let sel = state.plugin_selection.clone();
    let active_rules = state.active_cve_rules.read().await.clone();
    let ignored_cwes = state.ignored_cwes.read().await.clone();

    let scan_root = p_root.clone();
    let mut updated_graph = tokio::task::spawn_blocking(move || {
        let scanner = ProjectScanner::default().with_plugin_selection(sel);
        scanner.scan_project_with_exclusions(&scan_root, &excl)
    })
    .await
    .unwrap_or_else(|_| core_graph::graph::AetherGraph::new("Project"));

    crate::apply_settings_filters_to_graph(
        &mut updated_graph,
        active_rules.as_deref(),
        &ignored_cwes,
    );

    let (violations, file_count) = extract_live_audit_from_graph(&updated_graph);
    let _ = AuditWriter::write_live_audit(&p_root, &violations, file_count);

    let tn = updated_graph.nodes.len();
    let te = updated_graph.edges.len();
    *state.code_graph.write().await = Some(updated_graph.clone());

    let mode = state.get_active_view_mode().await;
    if mode != "vault" {
        *state.graph.write().await = updated_graph;
        *state.ui_graph_cache.write().await = None;
        state
            .graph_version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    (tn, te)
}

pub async fn get_plugins_handler(
    State(state): State<Arc<AppState>>,
) -> Json<PluginsInventoryResponse> {
    let p_root = state.project_root.read().await.clone();
    let inventory = tokio::task::spawn_blocking(move || build_plugins_inventory(&p_root))
        .await
        .unwrap_or_else(|_| PluginsInventoryResponse {
            status: "ok".to_string(),
            plugins_dir: ".aether/plugins".to_string(),
            community_bundle_installed: false,
            community_bundle_rules_count: 24,
            total_plugins: 0,
            enabled_plugins: 0,
            total_active_rules: 0,
            total_taint_sources: 0,
            total_taint_sinks: 0,
            total_sanitizers: 0,
            plugins: Vec::new(),
        });
    Json(inventory)
}

pub async fn toggle_plugin_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TogglePluginRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let p_root = state.project_root.read().await.clone();
    let target = resolve_confined_plugin_file(&p_root, &req.rel_path)?;

    let content = fs::read_to_string(&target).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Failed to read plugin: {e}") })),
        )
    })?;
    let mut manifest = parse_manifest_str(&content).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": format!("Invalid plugin manifest: {e}") })),
        )
    })?;
    manifest.enabled = req.enabled;

    let is_json = target
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let serialized = if is_json {
        serde_json::to_string_pretty(&manifest).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": format!("JSON serialization error: {e}") })),
            )
        })?
    } else {
        serde_yaml::to_string(&manifest).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": format!("YAML serialization error: {e}") })),
            )
        })?
    };

    fs::write(&target, serialized).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Failed to save plugin: {e}") })),
        )
    })?;

    let (total_nodes, total_edges) = rescan_after_plugin_mutation(&state).await;
    let inventory = build_plugins_inventory(&p_root);

    Ok(Json(json!({
        "status": "ok",
        "plugin": manifest.name,
        "enabled": manifest.enabled,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "inventory": inventory
    })))
}

pub async fn test_plugins_handler(
    State(state): State<Arc<AppState>>,
    req_opt: Option<Json<TestPluginsRequest>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let p_root = state.project_root.read().await.clone();
    let rel_opt = req_opt.and_then(|j| j.0.rel_path);

    let mut engine = PluginEngine::new();
    if let Some(rel_path) = rel_opt.filter(|s| !s.trim().is_empty()) {
        let target = resolve_confined_plugin_file(&p_root, &rel_path)?;
        let content = fs::read_to_string(&target).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": format!("Read error: {e}") })),
            )
        })?;
        engine.load_from_str(&content).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "message": format!("Parse error: {e}") })),
            )
        })?;
        if let Some(last) = engine.plugins.last_mut() {
            // Allow testing a plugin even if currently disabled.
            last.enabled = true;
        }
    } else {
        let plugins_dir = p_root.join(".aether").join("plugins");
        if plugins_dir.is_dir() {
            let _ = engine.load_from_directory(&plugins_dir);
        }
    }

    let report = engine.run_test_suite();
    Ok(Json(json!({
        "status": if report.failed == 0 { "passed" } else { "failed" },
        "total_tests": report.total_tests,
        "passed": report.passed,
        "failed": report.failed,
        "failures": report.failures
    })))
}

pub async fn init_bundle_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let p_root = state.project_root.read().await.clone();
    let plugins_dir = p_root.join(".aether").join("plugins");
    let out_path = CommunityBundle::unpack_to_directory(&plugins_dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Failed to unpack community bundle: {e}") })),
        )
    })?;

    let (total_nodes, total_edges) = rescan_after_plugin_mutation(&state).await;
    let inventory = build_plugins_inventory(&p_root);

    Ok(Json(json!({
        "status": "ok",
        "path": out_path.to_string_lossy(),
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "inventory": inventory
    })))
}

pub async fn import_semgrep_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportSemgrepRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let slug = sanitize_plugin_slug(&req.plugin_name).map_err(|msg| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg })),
        )
    })?;
    if req.yaml_content.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Semgrep YAML content cannot be empty" })),
        ));
    }

    let rule_file = SemgrepImporter::parse_yaml(&req.yaml_content).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": e })),
        )
    })?;
    if rule_file.rules.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "No Semgrep rules found in YAML input" })),
        ));
    }
    let manifest = SemgrepImporter::to_plugin_manifest(&rule_file, &slug).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": e })),
        )
    })?;

    let p_root = state.project_root.read().await.clone();
    let plugins_dir = p_root.join(".aether").join("plugins");
    let imported_dir = plugins_dir.join("imported");
    let target_dir = push_normal_rel_path(&imported_dir, &slug).map_err(|msg| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg })),
        )
    })?;
    let yaml_path = target_dir.join("plugin.yaml");
    fs::create_dir_all(&target_dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Cannot create plugin dir: {e}") })),
        )
    })?;
    let yaml_str = serde_yaml::to_string(&manifest).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("YAML serialization error: {e}") })),
        )
    })?;
    fs::write(&yaml_path, yaml_str).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Failed to write plugin: {e}") })),
        )
    })?;

    let (total_nodes, total_edges) = rescan_after_plugin_mutation(&state).await;
    let inventory = build_plugins_inventory(&p_root);

    Ok(Json(json!({
        "status": "ok",
        "plugin": slug,
        "rules_imported": manifest.rules.len(),
        "rel_path": format!("imported/{slug}/plugin.yaml"),
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "inventory": inventory
    })))
}

pub async fn upsert_plugin_rule_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpsertPluginRuleRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let slug = sanitize_plugin_slug(&req.plugin_name).map_err(|msg| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg })),
        )
    })?;
    let has_taint_payload =
        req.taint_sources.is_some() || req.taint_sinks.is_some() || req.sanitizers.is_some();
    let is_taint_only = req.rule_id.trim().is_empty() && has_taint_payload;

    if !is_taint_only {
        if req.rule_id.trim().is_empty() || req.cwe_id.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "message": "rule_id and cwe_id are required" })),
            ));
        }
        if req.file_extensions.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "message": "At least one file_extension is required (e.g. .rs, .ts, .py)" })),
            ));
        }
    }

    let p_root = state.project_root.read().await.clone();
    let plugins_dir = p_root.join(".aether").join("plugins");
    let primary_dir = push_normal_rel_path(&plugins_dir, &slug).map_err(|msg| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg })),
        )
    })?;
    let imported_candidate = plugins_dir.join("imported").join(&slug);
    let target_dir = if !primary_dir.join("plugin.yaml").is_file()
        && imported_candidate.join("plugin.yaml").is_file()
    {
        imported_candidate
    } else {
        primary_dir
    };
    let yaml_path = target_dir.join("plugin.yaml");

    let mut manifest = if yaml_path.is_file() {
        let existing = fs::read_to_string(&yaml_path).unwrap_or_default();
        parse_manifest_str(&existing).unwrap_or_else(|_| PluginManifest {
            name: slug.clone(),
            version: "1.0.0".to_string(),
            author: Some("AetherScope Cockpit".to_string()),
            description: Some(format!("Custom security plugin: {slug}")),
            enabled: true,
            ..Default::default()
        })
    } else {
        PluginManifest {
            name: slug.clone(),
            version: "1.0.0".to_string(),
            author: Some("AetherScope Cockpit".to_string()),
            description: Some(format!("Custom security plugin: {slug}")),
            enabled: true,
            ..Default::default()
        }
    };

    if let Some(desc) = req.plugin_description.filter(|s| !s.trim().is_empty()) {
        manifest.description = Some(desc);
    }
    if let Some(prof) = req.profile {
        let trimmed = prof.trim().to_string();
        manifest.profile = if trimmed.is_empty() { None } else { Some(trimmed) };
    }
    if let Some(tags) = req.tags {
        manifest.tags = tags
            .into_iter()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
    }
    if let Some(sources) = req.taint_sources {
        manifest.taint_sources = sources;
    }
    if let Some(sinks) = req.taint_sinks {
        manifest.taint_sinks = sinks;
    }
    if let Some(sans) = req.sanitizers {
        manifest.sanitizers = sans;
    }

    let mut saved_rule_id = String::from("TAINT-SSA-CONFIG");
    if !is_taint_only {
        let match_mode = match req.match_mode.as_deref() {
            Some("whole_file") => MatchMode::WholeFile,
            _ => MatchMode::LineByLine,
        };

        let ast_scope = req
            .ast_scope
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let mut new_rule = PluginRule {
            id: req.rule_id.trim().to_string(),
            cwe_id: req.cwe_id.trim().to_string(),
            name: if req.name.trim().is_empty() {
                req.rule_id.trim().to_string()
            } else {
                req.name.trim().to_string()
            },
            category: req
                .category
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "Custom / Security".to_string()),
            severity: req.severity.trim().to_ascii_uppercase(),
            description: req.description,
            remediation: req.remediation,
            file_extensions: req.file_extensions,
            match_mode,
            conditions: RuleConditions {
                must_contain: req.must_contain,
                must_not_contain: req.must_not_contain,
                regex_patterns: req.regex_patterns,
                forbidden_tokens: req.forbidden_tokens,
                check_literals: req.check_literals,
                not_preceded_within_lines: req.not_preceded_within_lines,
                in_path_matching: req.in_path_matching,
                not_in_path_matching: req.not_in_path_matching,
                ast_scope,
                ..Default::default()
            },
            test_cases: req.test_cases,
        };

        if let Err(msg) = new_rule.validate_regexes() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "message": msg })),
            ));
        }

        saved_rule_id = new_rule.id.clone();
        if let Some(pos) = manifest.rules.iter().position(|r| r.id == new_rule.id) {
            if new_rule.test_cases.is_empty() && !manifest.rules[pos].test_cases.is_empty() {
                new_rule.test_cases = manifest.rules[pos].test_cases.clone();
            }
            manifest.rules[pos] = new_rule;
        } else {
            manifest.rules.push(new_rule);
        }
    }

    // Certify embedded test cases before writing to disk.
    let mut test_engine = PluginEngine::new();
    let mut test_manifest = manifest.clone();
    test_manifest.enabled = true;
    test_manifest.precompile_all();
    test_engine.plugins.push(test_manifest);
    let report = test_engine.run_test_suite();
    if report.failed > 0 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "status": "failed",
                "message": format!("{} unit test(s) failed — plugin was NOT modified", report.failed),
                "total_tests": report.total_tests,
                "passed": report.passed,
                "failed": report.failed,
                "failures": report.failures
            })),
        ));
    }

    fs::create_dir_all(&target_dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Cannot create plugin dir: {e}") })),
        )
    })?;
    let yaml_str = serde_yaml::to_string(&manifest).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("YAML serialization error: {e}") })),
        )
    })?;
    fs::write(&yaml_path, yaml_str).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Failed to write plugin: {e}") })),
        )
    })?;

    let (total_nodes, total_edges) = rescan_after_plugin_mutation(&state).await;
    let inventory = build_plugins_inventory(&p_root);

    Ok(Json(json!({
        "status": "ok",
        "plugin": slug,
        "rule_id": saved_rule_id,
        "tests_passed": report.passed,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "inventory": inventory
    })))
}

pub async fn delete_plugin_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeletePluginRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let p_root = state.project_root.read().await.clone();
    let target = resolve_confined_plugin_file(&p_root, &req.rel_path)?;
    let plugins_dir = fs::canonicalize(p_root.join(".aether").join("plugins")).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Cannot canonicalize plugins dir: {e}") })),
        )
    })?;

    fs::remove_file(&target).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Failed to delete plugin file: {e}") })),
        )
    })?;

    // Clean up empty parent folder if strictly inside `.aether/plugins`.
    if let Some(parent) = target.parent() {
        if parent != plugins_dir && parent.starts_with(&plugins_dir) {
            let _ = fs::remove_dir(parent);
        }
    }

    let (total_nodes, total_edges) = rescan_after_plugin_mutation(&state).await;
    let inventory = build_plugins_inventory(&p_root);

    Ok(Json(json!({
        "status": "ok",
        "deleted": req.rel_path,
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "inventory": inventory
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sanitize_plugin_slug_rejects_traversal_and_invalid_chars() {
        assert_eq!(sanitize_plugin_slug("My Custom_Pack-1").unwrap(), "my-custom_pack-1");
        assert!(sanitize_plugin_slug("").is_err());
        assert!(sanitize_plugin_slug("../escape").is_err());
        assert!(sanitize_plugin_slug("a/b").is_err());
        assert!(sanitize_plugin_slug(r"a\b").is_err());
        assert!(sanitize_plugin_slug("C:evil").is_err());
        assert!(sanitize_plugin_slug("foo\0bar").is_err());
        assert!(sanitize_plugin_slug("...").is_err());
    }

    #[test]
    fn test_resolve_confined_plugin_file_blocks_escapes_and_bad_extensions() {
        let dir = tempdir().unwrap();
        let plugins_dir = dir.path().join(".aether").join("plugins").join("ok-pack");
        fs::create_dir_all(&plugins_dir).unwrap();
        fs::write(plugins_dir.join("plugin.yaml"), "name: ok\nversion: '1.0.0'\nrules: []\n").unwrap();
        fs::write(dir.path().join("secret.yaml"), "top: secret\n").unwrap();
        fs::write(plugins_dir.join("notes.txt"), "not yaml").unwrap();

        assert!(resolve_confined_plugin_file(dir.path(), "ok-pack/plugin.yaml").is_ok());
        assert!(resolve_confined_plugin_file(dir.path(), "../secret.yaml").is_err());
        assert!(resolve_confined_plugin_file(dir.path(), "../../secret.yaml").is_err());
        assert!(resolve_confined_plugin_file(dir.path(), "/etc/passwd").is_err());
        assert!(resolve_confined_plugin_file(dir.path(), "ok-pack/notes.txt").is_err());
    }

    #[test]
    fn test_build_plugins_inventory_reads_enabled_and_disabled_plugins() {
        let dir = tempdir().unwrap();
        let p1 = dir.path().join(".aether").join("plugins").join("pack-a");
        let p2 = dir.path().join(".aether").join("plugins").join("pack-b");
        fs::create_dir_all(&p1).unwrap();
        fs::create_dir_all(&p2).unwrap();
        fs::write(
            p1.join("plugin.yaml"),
            r#"
name: pack-a
version: "1.0.0"
enabled: true
profile: strict
tags: [rust, api]
rules:
  - id: CUSTOM-A-1
    cwe_id: CWE-89
    name: SQL Check
    severity: CRITICAL
    description: desc
    remediation: fix
    file_extensions: [".rs"]
    conditions:
      regex_patterns: ["raw_sql"]
      ast_scope: outside_test
      in_path_matching: ["src/api/**"]
      not_preceded_within_lines:
        lines: 3
        patterns: ["sanitize"]
"#,
        )
        .unwrap();
        fs::write(
            p2.join("plugin.yaml"),
            r#"
name: pack-b
version: "1.0.0"
enabled: false
rules:
  - id: CUSTOM-B-1
    cwe_id: CWE-79
    name: XSS Check
    severity: HIGH
    description: desc
    remediation: fix
    file_extensions: [".ts"]
"#,
        )
        .unwrap();

        let inv = build_plugins_inventory(dir.path());
        assert_eq!(inv.total_plugins, 2);
        assert_eq!(inv.enabled_plugins, 1);
        assert_eq!(inv.total_active_rules, 1);
        assert!(!inv.community_bundle_installed);
        assert_eq!(inv.community_bundle_rules_count, 24);
        assert_eq!(inv.plugins[0].profile.as_deref(), Some("strict"));
        assert_eq!(inv.plugins[0].rules[0].ast_scope.as_deref(), Some("outside_test"));
        assert!(inv.plugins[0].rules[0].not_preceded_within_lines.is_some());
    }

    #[test]
    fn test_apply_settings_filters_preserves_plugin_rules_with_native_active_list() {
        use core_graph::bubble::{CveAnomalyRecord, SymbolBubble, SymbolKind};
        use core_graph::graph::AetherGraph;

        let mut graph = AetherGraph::new("test-proj");
        let mut sym = SymbolBubble::new(
            "fn_auth".to_string(),
            "fn_auth".to_string(),
            "src/auth.rs".to_string(),
            10,
            SymbolKind::Function,
            "core".to_string(),
            "domain".to_string(),
        );
        sym.has_security_violation = true;
        sym.metadata.cve_anomalies = vec![
            CveAnomalyRecord {
                rule_id: "CVE-RUST-PANIC-DOS".to_string(),
                cve_id: "CWE-248".to_string(),
                severity: "HIGH".to_string(),
                message: "Native panic".to_string(),
                file_path: "src/auth.rs".to_string(),
                line_number: 10,
                remediation: "Handle error".to_string(),
                transmitted_data: None,
                transmitted_type: None,
                is_reachable: false,
                exploit_path: vec![],
                taint_trace: None,
            },
            CveAnomalyRecord {
                rule_id: "CVE-RUST-CMD-INJ".to_string(),
                cve_id: "CWE-78".to_string(),
                severity: "CRITICAL".to_string(),
                message: "Disabled native rule".to_string(),
                file_path: "src/auth.rs".to_string(),
                line_number: 15,
                remediation: "Validate args".to_string(),
                transmitted_data: None,
                transmitted_type: None,
                is_reachable: false,
                exploit_path: vec![],
                taint_trace: None,
            },
            CveAnomalyRecord {
                rule_id: "PLUGIN-CUSTOM-AUTH-BYPASS".to_string(),
                cve_id: "CWE-287 / AUTH-BYPASS".to_string(),
                severity: "CRITICAL".to_string(),
                message: "[Plugin: custom] Missing check".to_string(),
                file_path: "src/auth.rs".to_string(),
                line_number: 20,
                remediation: "Check token".to_string(),
                transmitted_data: None,
                transmitted_type: None,
                is_reachable: false,
                exploit_path: vec![],
                taint_trace: None,
            },
        ];
        graph.nodes.push(sym);

        // 1. Saved active_cve_rules only contains native CVE-RUST-PANIC-DOS -> plugin rule MUST survive!
        let mut g1 = graph.clone();
        let active_native_only = vec!["CVE-RUST-PANIC-DOS".to_string()];
        crate::apply_settings_filters_to_graph(&mut g1, Some(&active_native_only), &[]);
        let ids1: Vec<&str> = g1.nodes[0]
            .metadata
            .cve_anomalies
            .iter()
            .map(|a| a.rule_id.as_str())
            .collect();
        assert!(ids1.contains(&"CVE-RUST-PANIC-DOS"));
        assert!(!ids1.contains(&"CVE-RUST-CMD-INJ"), "Unchecked native rule must be filtered");
        assert!(
            ids1.contains(&"PLUGIN-CUSTOM-AUTH-BYPASS"),
            "Custom plugin rule must NOT be silently dropped by native active_cve_rules list"
        );
        assert!(g1.nodes[0].has_security_violation);

        // 2. Explicit ignored_cwes MUST still mute the custom plugin rule!
        let mut g2 = graph.clone();
        crate::apply_settings_filters_to_graph(
            &mut g2,
            Some(&active_native_only),
            &["PLUGIN-CUSTOM-AUTH-BYPASS".to_string()],
        );
        let ids2: Vec<&str> = g2.nodes[0]
            .metadata
            .cve_anomalies
            .iter()
            .map(|a| a.rule_id.as_str())
            .collect();
        assert!(!ids2.contains(&"PLUGIN-CUSTOM-AUTH-BYPASS"));

        // 3. Explicit empty active_cve_rules ("Tout Couper") mutes both native and plugin alerts.
        let mut g3 = graph.clone();
        crate::apply_settings_filters_to_graph(&mut g3, Some(&[]), &[]);
        assert!(g3.nodes[0].metadata.cve_anomalies.is_empty());
        assert!(!g3.nodes[0].has_security_violation);
    }

    #[tokio::test]
    async fn test_plugin_http_handlers_end_to_end() {
        use obsidian_vault::DetectedProjectType;

        let dir = tempdir().unwrap();
        let src_dir = dir.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(
            src_dir.join("app.rs"),
            "pub fn admin_wipe() { danger_exec(); }\n",
        )
        .unwrap();

        let state = Arc::new(AppState::new(
            core_graph::graph::AetherGraph::new("test"),
            dir.path().to_path_buf(),
            DetectedProjectType::PureCode,
            "code".to_string(),
            None,
            None,
            None,
        ));

        // 1. Upsert a DSL v2 rule with unit tests -> passes & writes plugin.yaml
        let upsert_res = upsert_plugin_rule_handler(
            State(state.clone()),
            Json(UpsertPluginRuleRequest {
                plugin_name: "Custom Guard".to_string(),
                profile: Some("strict".to_string()),
                tags: Some(vec!["rust".to_string()]),
                plugin_description: Some("Guard pack".to_string()),
                rule_id: "CUSTOM-DANGER-EXEC".to_string(),
                cwe_id: "CWE-78".to_string(),
                name: "Forbid danger_exec".to_string(),
                category: Some("Custom / Security".to_string()),
                severity: "CRITICAL".to_string(),
                description: "Detected danger_exec".to_string(),
                remediation: "Remove danger_exec".to_string(),
                file_extensions: vec![".rs".to_string()],
                match_mode: Some("line_by_line".to_string()),
                must_contain: vec![],
                must_not_contain: vec![],
                regex_patterns: vec!["danger_exec\\s*\\(".to_string()],
                forbidden_tokens: vec![],
                check_literals: false,
                not_preceded_within_lines: Some(PrecededWindowCondition {
                    lines: 2,
                    patterns: vec!["authorize\\(".to_string()],
                }),
                in_path_matching: vec!["src/**".to_string()],
                not_in_path_matching: vec![],
                ast_scope: Some("outside_test".to_string()),
                test_cases: vec![
                    RuleTestCase {
                        name: "vulnerable".to_string(),
                        file_name: "src/app.rs".to_string(),
                        code: "pub fn f() {\n    danger_exec();\n}".to_string(),
                        should_trigger: true,
                    },
                    RuleTestCase {
                        name: "guarded".to_string(),
                        file_name: "src/app.rs".to_string(),
                        code: "pub fn f() {\n    authorize();\n    danger_exec();\n}".to_string(),
                        should_trigger: false,
                    },
                ],
                taint_sources: None,
                taint_sinks: None,
                sanitizers: None,
            }),
        )
        .await
        .expect("upsert should succeed");
        assert_eq!(upsert_res.0["status"], "ok");
        assert_eq!(upsert_res.0["tests_passed"], 2);

        // 2. Toggle plugin OFF
        let toggle_res = toggle_plugin_handler(
            State(state.clone()),
            Json(TogglePluginRequest {
                rel_path: "custom-guard/plugin.yaml".to_string(),
                enabled: false,
            }),
        )
        .await
        .expect("toggle should succeed");
        assert_eq!(toggle_res.0["enabled"], false);
        assert_eq!(toggle_res.0["inventory"]["enabled_plugins"], 0);

        // 3. Test single plugin explicitly (even while disabled)
        let test_res = test_plugins_handler(
            State(state.clone()),
            Some(Json(TestPluginsRequest {
                rel_path: Some("custom-guard/plugin.yaml".to_string()),
            })),
        )
        .await
        .expect("test should succeed");
        assert_eq!(test_res.0["status"], "passed");
        assert_eq!(test_res.0["passed"], 2);

        // 4. Unpack community bundle
        let bundle_res = init_bundle_handler(State(state.clone()))
            .await
            .expect("init_bundle should succeed");
        assert_eq!(bundle_res.0["inventory"]["community_bundle_installed"], true);

        // 5. Import Semgrep YAML
        let semgrep_res = import_semgrep_handler(
            State(state.clone()),
            Json(ImportSemgrepRequest {
                plugin_name: "semgrep-demo".to_string(),
                yaml_content: r#"
rules:
  - id: demo-eval-js
    languages: [javascript]
    severity: ERROR
    message: Avoid eval
    metadata:
      cwe: "CWE-94"
    pattern: "eval($X)"
"#
                .to_string(),
            }),
        )
        .await
        .expect("import_semgrep should succeed");
        assert_eq!(semgrep_res.0["rules_imported"], 1);

        // 6. Delete custom-guard plugin
        let del_res = delete_plugin_handler(
            State(state.clone()),
            Json(DeletePluginRequest {
                rel_path: "custom-guard/plugin.yaml".to_string(),
            }),
        )
        .await
        .expect("delete should succeed");
        assert_eq!(del_res.0["status"], "ok");
    }

    #[tokio::test]
    async fn test_taint_ssa_configurator_coherence_and_visual_dir_isolation() {
        use obsidian_vault::DetectedProjectType;

        let dir = tempdir().unwrap();
        // Create a visual plugin under .aether/plugins/visuals/neon-test/visual-plugin.yaml
        let vis_dir = dir
            .path()
            .join(".aether")
            .join("plugins")
            .join("visuals")
            .join("neon-test");
        fs::create_dir_all(&vis_dir).unwrap();
        fs::write(
            vis_dir.join("visual-plugin.yaml"),
            "schema_version: 1\nid: neon-test\nname: Neon Test\nversion: '1.0.0'\nenabled: true\n",
        )
        .unwrap();

        let state = Arc::new(AppState::new(
            core_graph::graph::AetherGraph::new("test"),
            dir.path().to_path_buf(),
            DetectedProjectType::PureCode,
            "code".to_string(),
            None,
            None,
            None,
        ));

        // 1. Visual plugin must NOT leak into SAST plugins inventory
        let inv0 = build_plugins_inventory(dir.path());
        assert_eq!(inv0.total_plugins, 0);

        // 2. Deserialize a UI Configurateur Taint Dataflow SSA payload (with EnvironmentVar, Deserialization, CodeEval, Custom, and Sanitizer patterns + neutralizes_cwes)
        let ui_taint_payload: UpsertPluginRuleRequest = serde_json::from_value(json!({
            "plugin_name": "majestic-taint-ssa",
            "rule_id": "",
            "cwe_id": "",
            "taint_sources": [
                {
                    "name": "env_input",
                    "source_kind": "EnvironmentVar",
                    "cwe": "CWE-78",
                    "patterns": ["std::env::var", "process.env"]
                },
                {
                    "name": "custom_bus",
                    "source_kind": "Custom",
                    "cwe": "CWE-502",
                    "patterns": ["bus.recv("]
                }
            ],
            "taint_sinks": [
                {
                    "name": "deser_sink",
                    "rule_id": "TAINT-DESER-001",
                    "sink_kind": "Deserialization",
                    "cwe": "CWE-502",
                    "severity": "CRITICAL",
                    "patterns": ["pickle.loads", "bincode::deserialize"]
                },
                {
                    "name": "eval_sink",
                    "rule_id": "TAINT-EVAL-001",
                    "sink_kind": "CodeEval",
                    "cwe": "CWE-94",
                    "severity": "CRITICAL",
                    "patterns": ["eval("]
                }
            ],
            "sanitizers": [
                {
                    "name": "strict_guard",
                    "patterns": ["PathGuard::validate", "verify_schema"],
                    "neutralizes_cwes": ["CWE-502", "CWE-78"]
                }
            ]
        }))
        .expect("UI Taint SSA payload must deserialize without 422 error");

        let res = upsert_plugin_rule_handler(State(state.clone()), Json(ui_taint_payload))
            .await
            .expect("taint-only upsert must succeed");
        assert_eq!(res.0["status"], "ok");
        assert_eq!(res.0["inventory"]["total_plugins"], 1);
        assert_eq!(res.0["inventory"]["total_taint_sources"], 2);
        assert_eq!(res.0["inventory"]["total_taint_sinks"], 2);
        assert_eq!(res.0["inventory"]["total_sanitizers"], 1);

        // Verify the saved sanitizer matches by pattern and CWE
        let inv1 = build_plugins_inventory(dir.path());
        let san = &inv1.plugins[0].sanitizers[0];
        assert!(san.matches("verify_schema(payload)", "CWE-502"));
        assert!(!san.matches("verify_schema(payload)", "CWE-89"));
    }
}
