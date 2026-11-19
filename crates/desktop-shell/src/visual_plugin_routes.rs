use crate::api_routes::{save_project_settings, AppState, SettingsPayload};
use crate::plugin_routes::sanitize_plugin_slug;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use security_linter::SecretGuard;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

pub const MAX_GLSL_BYTES: usize = 32 * 1024;
const MAX_FOR_LOOP_BOUND: u32 = 128;

fn default_schema_version() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_version() -> String {
    "1.0.0".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VisualPaletteConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub background: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub layers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub severities: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VisualOverlayConfig {
    /// "organic_12lobe" | "hex_hull" | "rect_blueprint" | "none"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membrane_style: Option<String>,
    /// "bezier" | "straight" | "orthogonal_pcb"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_style: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_pulse_speed: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membrane_breath_amp: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_font: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VisualShaderConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backdrop: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_sdf: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub uniforms: HashMap<String, f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualPluginManifest {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub palette: VisualPaletteConfig,
    #[serde(default)]
    pub overlay: VisualOverlayConfig,
    #[serde(default)]
    pub shaders: VisualShaderConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct VisualPluginResolved {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub builtin: bool,
    pub rel_dir: String,
    pub palette: VisualPaletteConfig,
    pub overlay: VisualOverlayConfig,
    pub uniforms: HashMap<String, f32>,
    pub backdrop_glsl: Option<String>,
    pub node_sdf_glsl: Option<String>,
    pub validation_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VisualPluginsInventoryResponse {
    pub status: String,
    pub visuals_dir: String,
    pub active_visual_plugin: String,
    pub visual_version: u64,
    pub plugins: Vec<VisualPluginResolved>,
}

#[derive(Debug, Deserialize)]
pub struct ActivateVisualPluginRequest {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteVisualPluginRequest {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct UpsertVisualPluginRequest {
    pub id: String,
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub palette: VisualPaletteConfig,
    #[serde(default)]
    pub overlay: VisualOverlayConfig,
    #[serde(default)]
    pub uniforms: HashMap<String, f32>,
    #[serde(default)]
    pub backdrop_glsl: Option<String>,
    #[serde(default)]
    pub node_sdf_glsl: Option<String>,
    #[serde(default)]
    pub activate: bool,
}

/// Static anti-DoS and contract validation for GLSL ES 3.00 visual plugin hooks.
pub fn validate_glsl_hook(src: &str, expected_fn: &str) -> Result<(), String> {
    if src.len() > MAX_GLSL_BYTES {
        return Err(format!(
            "GLSL hook exceeds maximum allowed size ({} > {} bytes)",
            src.len(),
            MAX_GLSL_BYTES
        ));
    }
    if src.contains('\0') {
        return Err("GLSL hook contains forbidden null byte".to_string());
    }

    // Strip single-line and block comments for structural checks
    let mut cleaned = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else {
            cleaned.push(bytes[i] as char);
            i += 1;
        }
    }

    for line in cleaned.lines() {
        let t = line.trim();
        if t.starts_with("#version") || t.starts_with("#extension") || t.starts_with("#pragma") {
            return Err(format!(
                "Preprocessor directive '{}' is controlled by the AetherScope host shader and forbidden in hooks",
                t.split_whitespace().next().unwrap_or("#")
            ));
        }
    }

    let lower = cleaned.to_ascii_lowercase();
    if contains_keyword_before_paren(&lower, "while") {
        return Err("Unbounded 'while' loops are forbidden in visual plugin GLSL hooks (anti-TDR guard)".to_string());
    }
    if contains_do_loop(&lower) {
        return Err("Unbounded 'do { ... } while' loops are forbidden in visual plugin GLSL hooks".to_string());
    }

    // Inspect `for (...)` headers to reject infinite loops or huge constant bounds (> 128)
    validate_for_loops(&cleaned)?;

    if !cleaned.contains(expected_fn) {
        return Err(format!(
            "GLSL hook must define required contract function '{}'",
            expected_fn
        ));
    }

    Ok(())
}

fn contains_keyword_before_paren(lower: &str, kw: &str) -> bool {
    let bytes = lower.as_bytes();
    let kw_bytes = kw.as_bytes();
    let mut idx = 0;
    while let Some(pos) = lower[idx..].find(kw) {
        let abs = idx + pos;
        let prev_ok = abs == 0 || !(bytes[abs - 1].is_ascii_alphanumeric() || bytes[abs - 1] == b'_');
        let after = abs + kw_bytes.len();
        if prev_ok {
            let rest = lower[after..].trim_start();
            if rest.starts_with('(') {
                return true;
            }
        }
        idx = after;
    }
    false
}

fn contains_do_loop(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut idx = 0;
    while let Some(pos) = lower[idx..].find("do") {
        let abs = idx + pos;
        let prev_ok = abs == 0 || !(bytes[abs - 1].is_ascii_alphanumeric() || bytes[abs - 1] == b'_');
        let after = abs + 2;
        if prev_ok {
            let rest = lower[after..].trim_start();
            if rest.starts_with('{') {
                return true;
            }
        }
        idx = after;
    }
    false
}

fn validate_for_loops(src: &str) -> Result<(), String> {
    let bytes = src.as_bytes();
    let mut idx = 0;
    while let Some(pos) = src[idx..].find("for") {
        let abs = idx + pos;
        let prev_ok = abs == 0 || !(bytes[abs - 1].is_ascii_alphanumeric() || bytes[abs - 1] == b'_');
        let after = abs + 3;
        if prev_ok {
            let rest = src[after..].trim_start();
            if let Some(after_open) = rest.strip_prefix('(') {
                if let Some(close) = after_open.find(')') {
                    let header = &after_open[..close];
                    let parts: Vec<&str> = header.split(';').collect();
                    if parts.len() != 3 || parts[1].trim().is_empty() {
                        return Err("Unbounded 'for' loop detected in GLSL hook".to_string());
                    }
                    // Reject any numeric literal in loop condition larger than MAX_FOR_LOOP_BOUND
                    let cond = parts[1];
                    let mut num_buf = String::new();
                    for ch in cond.chars().chain(std::iter::once(' ')) {
                        if ch.is_ascii_digit() {
                            num_buf.push(ch);
                        } else if !num_buf.is_empty() {
                            if let Ok(val) = num_buf.parse::<u32>() {
                                if val > MAX_FOR_LOOP_BOUND {
                                    return Err(format!(
                                        "GLSL 'for' loop bound {} exceeds safety limit of {}",
                                        val, MAX_FOR_LOOP_BOUND
                                    ));
                                }
                            }
                            num_buf.clear();
                        }
                    }
                }
            }
        }
        idx = after;
    }
    Ok(())
}

fn resolve_confined_visual_dir(project_root: &Path, slug: &str) -> Result<PathBuf, String> {
    let clean = sanitize_plugin_slug(slug)?;
    let visuals_dir = project_root.join(".aether").join("plugins").join("visuals");
    let mut out = visuals_dir.clone();
    for comp in Path::new(&clean).components() {
        match comp {
            Component::Normal(seg) => out.push(seg),
            _ => return Err("Invalid visual plugin slug component".to_string()),
        }
    }
    if SecretGuard::is_secret_path(&out) {
        return Err("Secret path prohibited".to_string());
    }
    Ok(out)
}

fn read_confined_glsl(pack_dir: &Path, file_name: &str, expected_fn: &str) -> Result<String, String> {
    let trimmed = file_name.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains(':')
        || trimmed.contains('\0')
        || !trimmed.to_ascii_lowercase().ends_with(".glsl")
    {
        return Err(format!(
            "Invalid GLSL shader filename '{}': must be a simple .glsl file inside the pack directory",
            trimmed
        ));
    }
    let mut target = pack_dir.to_path_buf();
    for comp in Path::new(trimmed).components() {
        match comp {
            Component::Normal(seg) => target.push(seg),
            _ => return Err("Forbidden path component in GLSL filename".to_string()),
        }
    }
    let canon_dir = fs::canonicalize(pack_dir).map_err(|e| format!("Canonicalize dir error: {e}"))?;
    let canon_file = fs::canonicalize(&target).map_err(|_| format!("Shader file '{trimmed}' not found"))?;
    if !canon_file.starts_with(&canon_dir) || !canon_file.is_file() {
        return Err("GLSL shader path escapes visual plugin directory".to_string());
    }
    let content = fs::read_to_string(&canon_file).map_err(|e| format!("Read shader error: {e}"))?;
    validate_glsl_hook(&content, expected_fn)?;
    Ok(content)
}

pub fn build_visual_plugins_inventory(
    project_root: &Path,
    active_visual_plugin: Option<String>,
    visual_version: u64,
) -> VisualPluginsInventoryResponse {
    let visuals_dir = project_root.join(".aether").join("plugins").join("visuals");
    let mut plugins = Vec::new();

    if visuals_dir.is_dir() {
        if let Ok(rd) = fs::read_dir(&visuals_dir) {
            let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
            dirs.sort();
            for pack_dir in dirs {
                let manifest_path = ["visual-plugin.yaml", "visual-plugin.yml", "visual-plugin.json"]
                    .iter()
                    .map(|f| pack_dir.join(f))
                    .find(|p| p.is_file());
                let Some(mpath) = manifest_path else {
                    continue;
                };
                let Ok(raw) = fs::read_to_string(&mpath) else {
                    continue;
                };
                let parsed: Result<VisualPluginManifest, _> =
                    serde_yaml::from_str(&raw).or_else(|_| serde_json::from_str(&raw));
                let Ok(manifest) = parsed else {
                    continue;
                };

                let mut warnings = Vec::new();
                let backdrop_glsl = match manifest.shaders.backdrop.as_deref() {
                    Some(fname) if !fname.trim().is_empty() => {
                        match read_confined_glsl(&pack_dir, fname, "aetherBackdrop") {
                            Ok(src) => Some(src),
                            Err(e) => {
                                warnings.push(format!("backdrop: {e}"));
                                None
                            }
                        }
                    }
                    _ => None,
                };
                let node_sdf_glsl = match manifest.shaders.node_sdf.as_deref() {
                    Some(fname) if !fname.trim().is_empty() => {
                        match read_confined_glsl(&pack_dir, fname, "aetherNodeSurface") {
                            Ok(src) => Some(src),
                            Err(e) => {
                                warnings.push(format!("node_sdf: {e}"));
                                None
                            }
                        }
                    }
                    _ => None,
                };

                let folder_name = pack_dir
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&manifest.id)
                    .to_string();

                plugins.push(VisualPluginResolved {
                    schema_version: manifest.schema_version,
                    id: manifest.id,
                    name: manifest.name,
                    version: manifest.version,
                    author: manifest.author,
                    description: manifest.description,
                    enabled: manifest.enabled,
                    builtin: false,
                    rel_dir: format!("visuals/{folder_name}"),
                    palette: manifest.palette,
                    overlay: manifest.overlay,
                    uniforms: manifest.shaders.uniforms,
                    backdrop_glsl,
                    node_sdf_glsl,
                    validation_warnings: warnings,
                });
            }
        }
    }

    VisualPluginsInventoryResponse {
        status: "ok".to_string(),
        visuals_dir: visuals_dir.to_string_lossy().to_string(),
        active_visual_plugin: active_visual_plugin.unwrap_or_else(|| "obsidian-nebula".to_string()),
        visual_version,
        plugins,
    }
}

async fn persist_active_visual_plugin_setting(state: &AppState, id: String) {
    *state.active_visual_plugin.write().await = Some(id.clone());
    let p_root = state.project_root.read().await.clone();
    let merged_payload = SettingsPayload {
        exclusions: state.custom_exclusions.read().await.clone(),
        active_cve_rules: state.active_cve_rules.read().await.clone(),
        ignored_cwes: Some(state.ignored_cwes.read().await.clone()),
        cve_catalogue: None,
        mcp_binary_path: None,
        show_alerts: *state.show_alerts.read().await,
        show_cwe_bubbles: *state.show_cwe_bubbles.read().await,
        show_cwe_titles: *state.show_cwe_titles.read().await,
        show_folder_titles: *state.show_folder_titles.read().await,
        show_file_titles: *state.show_file_titles.read().await,
        low_memory_mode: *state.low_memory_mode.read().await,
        active_visual_plugin: Some(id),
        ui_settings: state.saved_ui_settings.read().await.clone(),
        rescan: None,
    };
    save_project_settings(&p_root, &merged_payload);
}

pub async fn get_visual_plugins_handler(
    State(state): State<Arc<AppState>>,
) -> Json<VisualPluginsInventoryResponse> {
    let p_root = state.project_root.read().await.clone();
    let active = state.active_visual_plugin.read().await.clone();
    let ver = state
        .visual_plugins_version
        .load(std::sync::atomic::Ordering::SeqCst);
    let inv = tokio::task::spawn_blocking(move || build_visual_plugins_inventory(&p_root, active, ver))
        .await
        .unwrap_or_else(|_| VisualPluginsInventoryResponse {
            status: "ok".to_string(),
            visuals_dir: ".aether/plugins/visuals".to_string(),
            active_visual_plugin: "obsidian-nebula".to_string(),
            visual_version: ver,
            plugins: Vec::new(),
        });
    Json(inv)
}

pub async fn activate_visual_plugin_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ActivateVisualPluginRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let slug = sanitize_plugin_slug(&req.id).map_err(|msg| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg })),
        )
    })?;
    persist_active_visual_plugin_setting(&state, slug.clone()).await;
    let ver = state
        .visual_plugins_version
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        + 1;
    Ok(Json(json!({
        "status": "ok",
        "active_visual_plugin": slug,
        "visual_version": ver
    })))
}

pub async fn upsert_visual_plugin_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpsertVisualPluginRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let slug = sanitize_plugin_slug(&req.id).map_err(|msg| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg })),
        )
    })?;
    if req.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": "Visual plugin name cannot be empty" })),
        ));
    }

    let backdrop_src = req
        .backdrop_glsl
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(src) = backdrop_src {
        validate_glsl_hook(src, "aetherBackdrop").map_err(|msg| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "message": format!("Backdrop GLSL error: {msg}") })),
            )
        })?;
    }

    let node_src = req
        .node_sdf_glsl
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(src) = node_src {
        validate_glsl_hook(src, "aetherNodeSurface").map_err(|msg| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "message": format!("Node SDF GLSL error: {msg}") })),
            )
        })?;
    }

    let p_root = state.project_root.read().await.clone();
    let pack_dir = resolve_confined_visual_dir(&p_root, &slug).map_err(|msg| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg })),
        )
    })?;
    fs::create_dir_all(&pack_dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Cannot create visual plugin dir: {e}") })),
        )
    })?;

    if let Some(src) = backdrop_src {
        fs::write(pack_dir.join("backdrop.glsl"), src).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": format!("Failed to write backdrop.glsl: {e}") })),
            )
        })?;
    } else {
        let _ = fs::remove_file(pack_dir.join("backdrop.glsl"));
    }

    if let Some(src) = node_src {
        fs::write(pack_dir.join("node_sdf.glsl"), src).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "message": format!("Failed to write node_sdf.glsl: {e}") })),
            )
        })?;
    } else {
        let _ = fs::remove_file(pack_dir.join("node_sdf.glsl"));
    }

    let manifest = VisualPluginManifest {
        schema_version: 1,
        id: slug.clone(),
        name: req.name.trim().to_string(),
        version: if req.version.trim().is_empty() {
            "1.0.0".to_string()
        } else {
            req.version.trim().to_string()
        },
        author: req.author.filter(|s| !s.trim().is_empty()),
        description: req.description.filter(|s| !s.trim().is_empty()),
        enabled: true,
        palette: req.palette,
        overlay: req.overlay,
        shaders: VisualShaderConfig {
            backdrop: backdrop_src.map(|_| "backdrop.glsl".to_string()),
            node_sdf: node_src.map(|_| "node_sdf.glsl".to_string()),
            uniforms: req.uniforms,
        },
    };

    let yaml_str = serde_yaml::to_string(&manifest).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("YAML serialization error: {e}") })),
        )
    })?;
    fs::write(pack_dir.join("visual-plugin.yaml"), yaml_str).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Failed to write visual-plugin.yaml: {e}") })),
        )
    })?;

    if req.activate {
        persist_active_visual_plugin_setting(&state, slug.clone()).await;
    }

    let ver = state
        .visual_plugins_version
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        + 1;
    let active = state.active_visual_plugin.read().await.clone();
    let inventory = build_visual_plugins_inventory(&p_root, active, ver);

    Ok(Json(json!({
        "status": "ok",
        "id": slug,
        "visual_version": ver,
        "inventory": inventory
    })))
}

pub async fn delete_visual_plugin_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeleteVisualPluginRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let slug = sanitize_plugin_slug(&req.id).map_err(|msg| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg })),
        )
    })?;
    let p_root = state.project_root.read().await.clone();
    let visuals_root = p_root.join(".aether").join("plugins").join("visuals");
    let pack_dir = resolve_confined_visual_dir(&p_root, &slug).map_err(|msg| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "status": "error", "message": msg })),
        )
    })?;
    let canon_root = fs::canonicalize(&visuals_root).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": "Visual plugins directory not found" })),
        )
    })?;
    let canon_pack = fs::canonicalize(&pack_dir).map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "status": "error", "message": format!("Visual plugin '{}' not found", slug) })),
        )
    })?;
    if !canon_pack.starts_with(&canon_root) || canon_pack == canon_root {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "status": "error", "message": "Visual plugin path escapes boundary" })),
        ));
    }

    fs::remove_dir_all(&canon_pack).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": format!("Failed to delete visual plugin: {e}") })),
        )
    })?;

    if state.active_visual_plugin.read().await.as_deref() == Some(slug.as_str()) {
        persist_active_visual_plugin_setting(&state, "obsidian-nebula".to_string()).await;
    }

    let ver = state
        .visual_plugins_version
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        + 1;
    let active = state.active_visual_plugin.read().await.clone();
    let inventory = build_visual_plugins_inventory(&p_root, active, ver);

    Ok(Json(json!({
        "status": "ok",
        "deleted": slug,
        "visual_version": ver,
        "inventory": inventory
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_validate_glsl_hook_blocks_unsafe_constructs_and_accepts_valid_hooks() {
        let valid_bg = r#"
            vec3 aetherBackdrop(vec2 aspectUv, vec2 worldCam, float zoom, float timeSec) {
                for (int i = 0; i < 4; i++) { aspectUv *= 1.01; }
                return u_theme_colors[0];
            }
        "#;
        assert!(validate_glsl_hook(valid_bg, "aetherBackdrop").is_ok());

        assert!(validate_glsl_hook("#version 300 es\nvec3 aetherBackdrop(){}", "aetherBackdrop").is_err());
        assert!(validate_glsl_hook("#extension GL_EXT_foo : enable\nvec3 aetherBackdrop(){}", "aetherBackdrop").is_err());
        assert!(validate_glsl_hook("vec3 aetherBackdrop(){ while(true){} return vec3(0.0); }", "aetherBackdrop").is_err());
        assert!(validate_glsl_hook("vec3 aetherBackdrop(){ for(int i=0;i<999;i++){} return vec3(0.0); }", "aetherBackdrop").is_err());
        assert!(validate_glsl_hook("vec3 wrongName(){ return vec3(0.0); }", "aetherBackdrop").is_err());
    }

    #[tokio::test]
    async fn test_visual_plugin_http_handlers_end_to_end() {
        use obsidian_vault::DetectedProjectType;

        let dir = tempdir().unwrap();
        let state = Arc::new(AppState::new(
            core_graph::graph::AetherGraph::new("test"),
            dir.path().to_path_buf(),
            DetectedProjectType::PureCode,
            "code".to_string(),
            None,
            None,
            None,
        ));

        // 1. Upsert valid custom visual pack with GLSL hooks + activate
        let res = upsert_visual_plugin_handler(
            State(state.clone()),
            Json(UpsertVisualPluginRequest {
                id: "my-neon-grid".to_string(),
                name: "My Neon Grid".to_string(),
                version: "1.0.0".to_string(),
                author: Some("Lab".to_string()),
                description: Some("Custom neon grid".to_string()),
                palette: VisualPaletteConfig {
                    background: vec!["#040a0f".to_string(), "#06b6d4".to_string()],
                    ..Default::default()
                },
                overlay: VisualOverlayConfig {
                    membrane_style: Some("hex_hull".to_string()),
                    edge_style: Some("orthogonal_pcb".to_string()),
                    ..Default::default()
                },
                uniforms: HashMap::from([("grid_scale".to_string(), 0.25)]),
                backdrop_glsl: Some(
                    "vec3 aetherBackdrop(vec2 uv, vec2 cam, float z, float t) { return u_theme_colors[0]; }".to_string(),
                ),
                node_sdf_glsl: Some(
                    "void aetherNodeSurface(in NodeCtx ctx, out vec3 rgb, out float alpha) { rgb = ctx.color.rgb; alpha = 1.0 - smoothstep(0.5, 0.9, ctx.r); }".to_string(),
                ),
                activate: true,
            }),
        )
        .await
        .expect("upsert visual plugin should succeed");
        assert_eq!(res.0["status"], "ok");
        assert_eq!(res.0["inventory"]["active_visual_plugin"], "my-neon-grid");
        assert_eq!(res.0["inventory"]["plugins"].as_array().unwrap().len(), 1);

        // 2. Reject path traversal id
        let bad = upsert_visual_plugin_handler(
            State(state.clone()),
            Json(UpsertVisualPluginRequest {
                id: "../evil".to_string(),
                name: "Evil".to_string(),
                version: "1.0.0".to_string(),
                author: None,
                description: None,
                palette: Default::default(),
                overlay: Default::default(),
                uniforms: Default::default(),
                backdrop_glsl: None,
                node_sdf_glsl: None,
                activate: false,
            }),
        )
        .await;
        assert!(bad.is_err());

        // 3. Delete resets active plugin back to obsidian-nebula
        let del = delete_visual_plugin_handler(
            State(state.clone()),
            Json(DeleteVisualPluginRequest {
                id: "my-neon-grid".to_string(),
            }),
        )
        .await
        .expect("delete should succeed");
        assert_eq!(del.0["inventory"]["active_visual_plugin"], "obsidian-nebula");
        assert_eq!(del.0["inventory"]["plugins"].as_array().unwrap().len(), 0);
    }
}
