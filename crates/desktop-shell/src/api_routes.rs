use core_graph::graph::AetherGraph;
use core_graph::manifest::{GalaxyManifest, ProjectManifest, StackType, TopologyMode};
use arch_templates::ArchScaffolder;
use ai_file_bridge::AuditWriter;
use security_linter::contract::ReadmeContract;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::RwLock;
use obsidian_vault::{
    DetectedProjectType, ProjectDetectionReport,
};

#[derive(Serialize, Clone)]
pub struct ProjectItem {
    pub name: String,
    pub path: String,
}

#[derive(Serialize)]
pub struct ProjectsResponse {
    pub projects: Vec<ProjectItem>,
    pub default_project: Option<String>,
}

#[derive(Deserialize)]
pub struct AnalyzeRequest {
    pub path: String,
    #[serde(default)]
    pub exclusions: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettingsPayload {
    #[serde(default)]
    pub exclusions: Vec<String>,
    #[serde(default)]
    pub active_cve_rules: Option<Vec<String>>,
    #[serde(default)]
    pub ignored_cwes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve_catalogue: Option<Vec<security_linter::CveRuleDef>>,
    /// Chemin réel de `aetherscope-mcp` (à côté de l'exécutable en cours) pour générer la config MCP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_binary_path: Option<String>,
}

/// Chemin absolu du binaire `aetherscope-mcp`, résolu relativement à l'exécutable courant.
pub fn resolve_mcp_binary_path() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let name = if cfg!(windows) { "aetherscope-mcp.exe" } else { "aetherscope-mcp" };
    Some(clean_path_string(&exe.parent()?.join(name)))
}

#[derive(Deserialize)]
pub struct ExportRequest {
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Serialize)]
pub struct ExportResponse {
    pub status: String,
    pub viewer_path: String,
    pub total_nodes: usize,
    pub total_edges: usize,
}

#[derive(Deserialize)]
pub struct SaveDocRequest {
    pub project_path: String,
    pub folder: String,
    pub file_name: String,
    pub content: String,
}

#[derive(Serialize)]
pub struct SaveDocResponse {
    pub status: String,
    pub saved_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blake3_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph: Option<AetherGraph>,
}

#[derive(Deserialize)]
pub struct SignContractsRequest {
    #[serde(default)]
    pub project_path: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
}

#[derive(Serialize)]
pub struct SignContractsResponse {
    pub status: String,
    pub message: String,
    pub signed_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blake3_hash: Option<String>,
    pub graph: AetherGraph,
}

#[derive(Deserialize)]
pub struct UpdateContractRequest {
    #[serde(default)]
    pub project_path: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default)]
    pub max_lines_per_file: Option<usize>,
    #[serde(default)]
    pub file_max_lines: Option<usize>,
    #[serde(default)]
    pub clear_file_override: bool,
    #[serde(default)]
    pub allowed_imports: Option<Vec<String>>,
    #[serde(default)]
    pub forbidden_imports: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct UpdateContractResponse {
    pub status: String,
    pub message: String,
    pub contract_path: String,
    pub blake3_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_blake3_hash: Option<String>,
    pub effective_max_lines: usize,
    pub graph: AetherGraph,
}

#[derive(Deserialize)]
pub struct AiTargetRequest {
    pub symbol_id: String,
    #[serde(default)]
    pub action_type: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AiTargetResponse {
    pub status: String,
    pub active_target_path: String,
    pub handshake_xml: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blake3_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_verified: Option<bool>,
    pub ears_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub galaxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docstring: Option<String>,
    #[serde(default)]
    pub callers: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categorized_incoming: Option<core_graph::edge::CategorizedLiaisons>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categorized_outgoing: Option<core_graph::edge::CategorizedLiaisons>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted_doc_and_liaisons: Option<String>,
}

#[derive(Deserialize)]
pub struct InitProjectRequest {
    pub path: String,
    #[serde(default = "default_stack")]
    pub stack: String, // "rust" | "python" | "ts" | "hybrid" | "mvc" | "roblox" | "minecraft"
    #[serde(default)]
    pub topology: Option<String>, // "local" | "dissociated"
}

fn default_stack() -> String {
    "hybrid".to_string()
}

#[derive(Serialize)]
pub struct InitProjectResponse {
    pub status: String,
    pub message: String,
    pub created_dirs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitFileStatusKind {
    Modified,
    Untracked,
    Staged,
    Deleted,
    Renamed,
    Conflict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitFileChange {
    pub path: String,
    pub status: GitFileStatusKind,
    pub index_code: char,
    pub worktree_code: char,
    pub has_security_violation: bool,
    pub cwe_count: usize,
    pub ears_violation: bool,
    pub max_severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitStatusResponse {
    pub is_git_repo: bool,
    pub branch: Option<String>,
    pub clean: bool,
    pub files: Vec<GitFileChange>,
    pub modified_count: usize,
    pub untracked_count: usize,
    pub staged_count: usize,
    pub deleted_count: usize,
    pub security_alert_count: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AiTelemetryEvent {
    pub target: String,
    pub action: String,
    pub details: String,
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AiChatMessage {
    pub id: String,
    pub sender: String,
    pub text: String,
    #[serde(default)]
    pub target_symbol: Option<String>,
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub recipient: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

#[derive(Deserialize)]
pub struct SendChatMessageRequest {
    pub text: String,
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default)]
    pub target_symbol: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub recipient: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

#[derive(Serialize)]
pub struct ChatMessagesResponse {
    pub messages: Vec<AiChatMessage>,
    pub agent_status: String,
}

#[derive(Deserialize)]
pub struct CreateTaskApiRequest {
    pub title: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub target_symbol: Option<String>,
    #[serde(default)]
    pub target_file: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub initial_readme: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateTaskApiRequest {
    pub task_id: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub progress: Option<u8>,
    #[serde(default)]
    pub progress_note: Option<String>,
    #[serde(default)]
    pub full_readme: Option<String>,
}

#[derive(Deserialize)]
pub struct DeleteTaskApiRequest {
    pub task_id: String,
}

#[derive(Deserialize)]
pub struct CreateFileRequest {
    pub project_path: String,
    pub file_path: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct LaunchCliRequest {
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub project_path: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
}

#[derive(Serialize)]
pub struct CreateFileResponse {
    pub status: String,
    pub file_path: String,
    pub created_symbol: String,
    pub graph: AetherGraph,
    pub data: AetherGraph,
}

#[derive(Serialize)]
pub struct PickWorkspaceResponse {
    pub status: String,
    pub workspace: Option<String>,
    pub projects: Vec<ProjectItem>,
}

#[derive(Serialize)]
pub struct PickProjectResponse {
    pub status: String,
    pub project_path: Option<String>,
    pub graph: Option<AetherGraph>,
}

// ─────────────────────────────────────────────────────────────────────────────
// M2: OBSIDIAN VAULT & DUAL-VISION MODELS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ViewModeRequest {
    pub mode: String, // "code" | "vault" (or "notes")
}

#[allow(dead_code)]
pub type SwitchViewModeRequest = ViewModeRequest;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectStatusResponse {
    pub status: String,
    pub project_type: String,
    pub has_obsidian_dir: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obsidian_dir_path: Option<String>,
    pub supported_views: Vec<String>,
    pub active_view_mode: String,
    pub active_view: String,
    pub code_files_count: usize,
    pub markdown_files_count: usize,
    pub obsidian_syntax_markers_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_report: Option<ProjectDetectionReport>,
}

#[derive(Debug, Clone)]
pub enum ViewModeError {
    InvalidMode(String),
    GraphNotAvailable(String),
}

impl std::fmt::Display for ViewModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ViewModeError::InvalidMode(s) => write!(f, "{}", s),
            ViewModeError::GraphNotAvailable(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for ViewModeError {}

pub struct AppState {
    pub graph: RwLock<AetherGraph>,
    pub project_root: RwLock<PathBuf>,
    pub telemetry: RwLock<Option<AiTelemetryEvent>>,
    pub active_agents: RwLock<std::collections::HashMap<String, AiTelemetryEvent>>,
    pub chat_messages: RwLock<Vec<AiChatMessage>>,
    pub graph_version: std::sync::atomic::AtomicU64,
    pub custom_exclusions: RwLock<Vec<String>>,
    pub active_cve_rules: RwLock<Option<Vec<String>>>,
    pub ignored_cwes: RwLock<Vec<String>>,

    // === Obsidian Vault & Dual-Vision Vision Mode Extensions (M2) ===
    pub project_type: RwLock<DetectedProjectType>,
    pub active_view_mode: RwLock<String>,
    pub code_graph: RwLock<Option<AetherGraph>>,
    pub vault_graph: RwLock<Option<AetherGraph>>,
    pub detection_report: RwLock<Option<ProjectDetectionReport>>,
}

impl AppState {
    pub fn new(
        graph: AetherGraph,
        project_root: PathBuf,
        project_type: DetectedProjectType,
        active_view_mode: String,
        code_graph: Option<AetherGraph>,
        vault_graph: Option<AetherGraph>,
        detection_report: Option<ProjectDetectionReport>,
    ) -> Self {
        Self {
            graph: RwLock::new(graph),
            project_root: RwLock::new(project_root),
            telemetry: RwLock::new(None),
            active_agents: RwLock::new(std::collections::HashMap::new()),
            chat_messages: RwLock::new(Vec::new()),
            graph_version: std::sync::atomic::AtomicU64::new(1),
            custom_exclusions: RwLock::new(Vec::new()),
            active_cve_rules: RwLock::new(None),
            ignored_cwes: RwLock::new(Vec::new()),
            project_type: RwLock::new(project_type),
            active_view_mode: RwLock::new(active_view_mode),
            code_graph: RwLock::new(code_graph),
            vault_graph: RwLock::new(vault_graph),
            detection_report: RwLock::new(detection_report),
        }
    }

    pub async fn get_active_view_mode(&self) -> String {
        self.active_view_mode.read().await.clone()
    }

    pub async fn get_project_type(&self) -> DetectedProjectType {
        *self.project_type.read().await
    }

    pub async fn get_detection_report(&self) -> Option<ProjectDetectionReport> {
        self.detection_report.read().await.clone()
    }

    pub async fn get_active_graph(&self) -> AetherGraph {
        self.graph.read().await.clone()
    }

    pub async fn get_code_graph(&self) -> Option<AetherGraph> {
        self.code_graph.read().await.clone()
    }

    pub async fn get_vault_graph(&self) -> Option<AetherGraph> {
        self.vault_graph.read().await.clone()
    }

    pub async fn get_supported_views(&self) -> Vec<String> {
        if let Some(rep) = self.detection_report.read().await.as_ref() {
            rep.supported_views.clone()
        } else {
            self.project_type.read().await.supported_views().into_iter().map(|s| s.to_string()).collect()
        }
    }

    pub async fn get_project_status(&self) -> ProjectStatusResponse {
        let p_type = *self.project_type.read().await;
        let report_guard = self.detection_report.read().await;
        let active_mode = self.active_view_mode.read().await.clone();

        if let Some(ref report) = *report_guard {
            ProjectStatusResponse {
                status: "ok".to_string(),
                project_type: report.project_type.as_str().to_string(),
                has_obsidian_dir: report.has_obsidian_dir,
                obsidian_dir_path: report.obsidian_dir_path.clone(),
                supported_views: report.supported_views.clone(),
                active_view_mode: active_mode.clone(),
                active_view: active_mode,
                code_files_count: report.code_files_count,
                markdown_files_count: report.markdown_files_count,
                obsidian_syntax_markers_count: report.obsidian_syntax_markers_count,
                detection_report: Some(report.clone()),
            }
        } else {
            let supported_views: Vec<String> = p_type
                .supported_views()
                .into_iter()
                .map(|s| s.to_string())
                .collect();
            ProjectStatusResponse {
                status: "ok".to_string(),
                project_type: p_type.as_str().to_string(),
                has_obsidian_dir: false,
                obsidian_dir_path: None,
                supported_views,
                active_view_mode: active_mode.clone(),
                active_view: active_mode,
                code_files_count: 0,
                markdown_files_count: 0,
                obsidian_syntax_markers_count: 0,
                detection_report: None,
            }
        }
    }

    pub async fn switch_view_mode(&self, requested_mode: &str) -> Result<AetherGraph, ViewModeError> {
        let norm_mode = match requested_mode.trim().to_lowercase().as_str() {
            "vault" | "notes" => "vault",
            "code" => "code",
            other => {
                return Err(ViewModeError::InvalidMode(format!(
                    "Mode de vue inconnu '{}'. Modes acceptés: 'code', 'vault'.",
                    other
                )));
            }
        };

        let target_graph = match norm_mode {
            "vault" => {
                let cached = self.vault_graph.read().await.clone();
                if let Some(g) = cached {
                    g
                } else {
                    let ptype = *self.project_type.read().await;
                    if ptype.is_vault() || ptype.is_mixed() {
                        let root = self.project_root.read().await.clone();
                        let scanned = tokio::task::spawn_blocking(move || {
                            obsidian_vault::scan_obsidian_vault(&root)
                        })
                        .await
                        .map_err(|e| ViewModeError::GraphNotAvailable(format!("Erreur join scan vault: {}", e)))?
                        .map_err(|e| ViewModeError::GraphNotAvailable(format!("Scan vault échoué: {}", e)))?;

                        *self.vault_graph.write().await = Some(scanned.clone());
                        scanned
                    } else {
                        return Err(ViewModeError::GraphNotAvailable(
                            "Aucun graphe Obsidian Vault n'est disponible pour ce projet.".to_string(),
                        ));
                    }
                }
            }
            "code" => {
                let cached = self.code_graph.read().await.clone();
                if let Some(g) = cached {
                    g
                } else {
                    let ptype = *self.project_type.read().await;
                    if ptype.is_code() || ptype.is_mixed() {
                        let root = self.project_root.read().await.clone();
                        let excl = self.custom_exclusions.read().await.clone();
                        let scanned = tokio::task::spawn_blocking(move || {
                            let scanner = ast_scanner::ProjectScanner::default();
                            scanner.scan_project_with_exclusions(&root, &excl)
                        })
                        .await
                        .map_err(|e| ViewModeError::GraphNotAvailable(format!("Erreur join scan code: {}", e)))?;

                        *self.code_graph.write().await = Some(scanned.clone());
                        scanned
                    } else {
                        return Err(ViewModeError::GraphNotAvailable(
                            "Aucun graphe AST Code n'est disponible pour ce projet.".to_string(),
                        ));
                    }
                }
            }
            _ => unreachable!(),
        };

        // Sequential non-nested lock updates
        {
            let mut active_mode_guard = self.active_view_mode.write().await;
            *active_mode_guard = norm_mode.to_string();
        }
        {
            let mut graph_guard = self.graph.write().await;
            *graph_guard = target_graph.clone();
        }
        self.graph_version.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let (action_title, details_msg) = if norm_mode == "vault" {
            (
                "Bascule Vision Vault",
                format!("Vue Notes & Relations Obsidian activée ({} nœuds)", target_graph.nodes.len()),
            )
        } else {
            (
                "Bascule Vision Code",
                format!("Vue Architecture & AST Code activée ({} symboles)", target_graph.nodes.len()),
            )
        };
        let mut t_guard = self.telemetry.write().await;
        *t_guard = Some(AiTelemetryEvent {
            target: "Cockpit".to_string(),
            action: action_title.to_string(),
            details: details_msg,
            timestamp: now_ms,
            ..Default::default()
        });

        Ok(target_graph)
    }
}


pub fn clean_path_string(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        s
    }
}

pub fn discover_candidate_projects(workspace_root: &Path) -> Vec<ProjectItem> {
    let mut candidates = Vec::new();

    if let Ok(entries) = fs::read_dir(workspace_root) {
        for entry in entries.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_dir() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if !name.starts_with('.') && name != "target" && name != "node_modules" && name != "dist" {
                        candidates.push(ProjectItem {
                            name,
                            path: clean_path_string(&entry.path()),
                        });
                    }
                }
            }
        }
    }

    if let Some(parent) = workspace_root.parent() {
        if let Ok(entries) = fs::read_dir(parent) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_dir() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        let p_str = clean_path_string(&entry.path());
                        if !name.starts_with('.') && name != "target" && !candidates.iter().any(|c| c.path == p_str) {
                            candidates.push(ProjectItem {
                                name,
                                path: p_str,
                            });
                        }
                    }
                }
            }
        }
    }

    candidates.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    candidates
}

/// Calcule les hashes BLAKE3 des contrats README.md et met à jour aether.lock.toml
pub fn sign_project_contracts(base: &Path, folder_filter: Option<&str>) -> Result<(usize, Option<String>), String> {
    let lock_file = base.join("aether.lock.toml");
    let proj_name = base
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    let mut manifest: ProjectManifest = if let Ok(lock_str) = fs::read_to_string(&lock_file) {
        toml::from_str(&lock_str).unwrap_or_else(|_| {
            ArchScaffolder::create_manifest(&proj_name, StackType::HybridMmoWeb3, TopologyMode::MonorepoLocal)
        })
    } else {
        ArchScaffolder::create_manifest(&proj_name, StackType::HybridMmoWeb3, TopologyMode::MonorepoLocal)
    };

    let mut signed_count = 0usize;
    let mut last_hash = None;

    let norm_filter = folder_filter.map(|f| {
        f.trim_start_matches("./")
            .trim_start_matches('/')
            .replace('\\', "/")
    });

    for entry in walkdir::WalkDir::new(base)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !name.starts_with('.') && name != "target" && name != "node_modules" && name != "dist"
        })
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() && entry.file_name().to_string_lossy().eq_ignore_ascii_case("README.md") {
            let rel_folder = entry
                .path()
                .parent()
                .and_then(|p| p.strip_prefix(base).ok())
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "root".to_string());

            if let Some(ref f) = norm_filter {
                if !f.is_empty() && f != &rel_folder && !(f == "." && rel_folder == "root") {
                    continue;
                }
            }

            if let Ok(content) = fs::read_to_string(entry.path()) {
                if let Ok(contract) = ReadmeContract::parse(&rel_folder, &content) {
                    let hash = contract.blake3_hash.clone();
                    last_hash = Some(hash.clone());
                    signed_count += 1;

                    let key = if rel_folder == "root" {
                        "root".to_string()
                    } else {
                        rel_folder.clone()
                    };

                    if let Some(gal) = manifest.galaxies.get_mut(&key) {
                        gal.readme_blake3 = Some(hash);
                    } else {
                        manifest.galaxies.insert(
                            key,
                            GalaxyManifest {
                                path: if rel_folder == "root" {
                                    ".".to_string()
                                } else {
                                    format!("./{}", rel_folder)
                                },
                                role: format!("Signed contract for {}", rel_folder),
                                remote_sync: false,
                                remote_endpoint: None,
                                readme_blake3: Some(hash),
                            },
                        );
                    }
                }
            }
        }
    }

    if let Ok(lock_str) = toml::to_string_pretty(&manifest) {
        fs::write(&lock_file, lock_str).map_err(|e| e.to_string())?;
    }

    Ok((signed_count, last_hash))
}

/// Met à jour le contrat README.md (pour un dossier ou un fichier spécifique) et scelle son empreinte BLAKE3 dans aether.lock.toml
pub fn update_contract_rules(
    base: &Path,
    req: &UpdateContractRequest,
) -> Result<(String, String, Option<String>, usize), String> {
    let norm_file = req.file_path.as_ref().map(|f| {
        f.trim_start_matches("./")
            .trim_start_matches('/')
            .replace('\\', "/")
    });

    // Déterminer le dossier cible du contrat README.md
    let target_folder = if let Some(ref f) = req.folder {
        let cf = f
            .trim_start_matches("./")
            .trim_start_matches('/')
            .trim_end_matches('/')
            .replace('\\', "/");
        if cf.is_empty() || cf == "." || cf == "root" {
            "root".to_string()
        } else {
            cf
        }
    } else if let Some(ref fp) = norm_file {
        // Remonter depuis le dossier parent du fichier jusqu'à trouver un README.md existant, sinon utiliser le dossier direct du fichier
        let file_folder = fp
            .rfind('/')
            .map(|idx| &fp[..idx])
            .unwrap_or("root");
        let mut chosen = file_folder.to_string();
        if chosen != "root" {
            let mut cur = file_folder;
            loop {
                if base.join(cur).join("README.md").exists() {
                    chosen = cur.to_string();
                    break;
                }
                if let Some(idx) = cur.rfind('/') {
                    cur = &cur[..idx];
                } else {
                    if base.join("README.md").exists() {
                        chosen = "root".to_string();
                    }
                    break;
                }
            }
        }
        chosen
    } else {
        "root".to_string()
    };

    let readme_path = if target_folder == "root" {
        base.join("README.md")
    } else {
        base.join(&target_folder).join("README.md")
    };

    // Si le README cible n'existe pas encore dans ce sous-dossier, hériter éventuellement du parent le plus proche
    let existing_content = if readme_path.exists() {
        fs::read_to_string(&readme_path).ok()
    } else {
        let mut parent_content = None;
        let mut cur = target_folder.as_str();
        while let Some(idx) = cur.rfind('/') {
            cur = &cur[..idx];
            let p_readme = base.join(cur).join("README.md");
            if p_readme.exists() {
                parent_content = fs::read_to_string(&p_readme).ok();
                break;
            }
        }
        if parent_content.is_none() {
            parent_content = fs::read_to_string(base.join("README.md")).ok();
        }
        parent_content
    };

    let file_override_arg = norm_file.as_deref().and_then(|fp| {
        if req.clear_file_override {
            Some((fp, None))
        } else {
            req.file_max_lines.map(|lim| (fp, Some(lim)))
        }
    });

    let updated_content = ReadmeContract::upsert_contract_content(
        existing_content.as_deref(),
        &target_folder,
        req.max_lines_per_file,
        file_override_arg,
        req.allowed_imports.clone(),
        req.forbidden_imports.clone(),
    );

    if let Some(parent) = readme_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&readme_path, &updated_content).map_err(|e| e.to_string())?;

    let parsed = ReadmeContract::parse(&target_folder, &updated_content)?;
    let _ = sign_project_contracts(base, Some(&target_folder))?;

    let file_blake3_hash = norm_file.as_ref().and_then(|fp| {
        let full_fp = base.join(fp);
        fs::read_to_string(&full_fp)
            .ok()
            .map(|s| ReadmeContract::compute_blake3_hex(&s))
    });

    let effective_max = if let Some(ref fp) = norm_file {
        parsed.effective_max_lines(fp)
    } else {
        parsed.frontmatter.max_lines_per_file
    };

    let rel_contract_path = if target_folder == "root" {
        "README.md".to_string()
    } else {
        format!("{}/README.md", target_folder)
    };

    Ok((
        rel_contract_path,
        parsed.blake3_hash,
        file_blake3_hash,
        effective_max,
    ))
}

#[allow(dead_code)]
pub fn init_project_structure(base: &Path, stack_str: &str) -> Vec<String> {
    init_project_structure_with_topology(base, stack_str, None)
}

pub fn init_project_structure_with_topology(
    base: &Path,
    stack_str: &str,
    topology_str: Option<&str>,
) -> Vec<String> {
    let _ = fs::create_dir_all(base);

    let stack = match stack_str.to_lowercase().as_str() {
        "rust" => StackType::PureRust,
        "python" => StackType::PurePythonUv,
        "ts" | "node" => StackType::PureNodePnpm,
        "roblox" | "roblox-server" | "luau" => StackType::RobloxLuau,
        "minecraft" | "mc" => StackType::MinecraftServer,
        "mvc" | "classic-mvc" | "clean-mvc" => StackType::ClassicMvc,
        _ => StackType::HybridMmoWeb3,
    };

    let topology = match topology_str.unwrap_or("local").to_lowercase().as_str() {
        "dissociated" | "distributed" => TopologyMode::Dissociated,
        _ => TopologyMode::MonorepoLocal,
    };

    let proj_name = base.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "project".to_string());
    let manifest = ArchScaffolder::create_manifest(&proj_name, stack.clone(), topology);

    let lock_file = base.join("aether.lock.toml");
    if let Ok(lock_str) = toml::to_string_pretty(&manifest) {
        let _ = fs::write(&lock_file, lock_str);
    }

    let (stack_title, stack_contract_note, stack_db_note) = match stack {
        StackType::PureRust => (
            "🦀 Rust (Cargo Workspace Hexagonal)",
            "Traits Rust stricts, DTOs partagés Serde et schémas RPC",
            "Trait RepositoryPort : bascule SQLite local (fichier) <-> Postgres distant par config",
        ),
        StackType::PurePythonUv => (
            "🐍 Python (Modular Clean Monorepo uv)",
            "Schémas Pydantic v2 stricts dans contracts/ validant I/O API et Workers",
            "SQLAlchemy 2 / SQLModel avec adaptateur SQLite local ou Postgres distant",
        ),
        StackType::PureNodePnpm => (
            "🟢 Node.js TypeScript (pnpm Workspace)",
            "Validation de bout en bout Zod + Routeurs tRPC / Hono",
            "Packages/db Drizzle ou Prisma isolable en microservice indépendant",
        ),
        StackType::HybridMmoWeb3 => (
            "⚡ Hybride Web3 & Temps Réel MMO",
            "Paquets WebSocket binaires, schémas RPC et ABIs Smart Contracts",
            "PostgreSQL State, Redis pub/sub temps réel et indexeurs On-Chain",
        ),
        StackType::RobloxLuau => (
            "🟥 Roblox Luau (Authoritative Game Server)",
            "RemoteEvents stricts, typage strict Luau (--!strict) et validation côté serveur",
            "DataStoreService avec Session-Locking (ProfileService pattern) anti-dupe",
        ),
        StackType::MinecraftServer => (
            "⛏️ Minecraft Game Server (Paper / Purpur)",
            "Manifest universel Aether, spécifications de plugins et tuning JVM Aikar",
            "Nœuds de données mondes, chunks pré-générés et persistance joueurs SQLite/MySQL",
        ),
        StackType::ClassicMvc => (
            "🏛️ Architecture MVC Propre (Modèle-Vue-Contrôleur)",
            "Contrats d'interfaces, DTOs stricts et validation des requêtes d'entrée",
            "Couche Modèles & Persistance isolable (SQLite/PostgreSQL/Redis)",
        ),
    };

    let structure = vec![
        ("contracts", format!("---\nid: contracts\nlayer: contracts\nmax_lines_per_file: 200\nallowed_imports: []\nforbidden_imports: [\"client::*\", \"server::*\"]\n---\n# 📜 Contrats Globaux & Interfaces Partagées\n\n> **Stack :** {}\n> **Rôle :** {}\n\n## 🛡️ Règles EARS\n- WHEN client issues API request THE SYSTEM SHALL validate schema.\n- WHEN server emits response THE SYSTEM SHALL guarantee type safety.\n", stack_title, stack_contract_note)),
        ("client", format!("---\nid: client\nlayer: ui\nmax_lines_per_file: 300\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"server::domain::*\", \"data-nodes::*\"]\n---\n# 💻 Couche Client (Interface & Présentation)\n\n> Rendu graphique, formulaires («Form») et gestion d'état local.\n\n- WHEN user interacts with view THE SYSTEM SHALL update reactive local state.\n")),
        ("client/ui", format!("---\nid: client-ui\nlayer: ui\nmax_lines_per_file: 250\nallowed_imports: [\"contracts::*\", \"client/state::*\"]\nforbidden_imports: [\"server::*\"]\n---\n# 🎨 Composants UI & Formulaires\n\nWHEN user submits form THE SYSTEM SHALL trigger client validation.\n")),
        ("client/state", format!("---\nid: client-state\nlayer: ui\nmax_lines_per_file: 200\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"server::domain::*\"]\n---\n# 🧠 Gestion d'État Client\n\nStockage réactif local et synchronisation des sessions.\n")),
        ("server", format!("---\nid: server\nlayer: domain\nmax_lines_per_file: 300\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"client::*\"]\nsecurity_rules:\n  no_raw_sql: true\n  no_env_access: true\n---\n# ⚡ Cœur Métier & API Serveur\n\n> Couche dissociable pouvant tourner en local ou sur serveur dédié.\n")),
        ("server/domain", format!("---\nid: server-domain\nlayer: domain\nmax_lines_per_file: 200\nallowed_imports: []\nforbidden_imports: [\"server/api::*\", \"client::*\", \"data-nodes::*\"]\nsecurity_rules:\n  deterministic_only: true\n---\n# 🏛️ Logique Métier Pure (Domain)\n\n100% pur, zéro dépendance I/O externe. Règles fondamentales immuables.\n\n- WHEN domain rule is evaluated THE SYSTEM SHALL execute deterministically without I/O.\n")),
        ("server/application", format!("---\nid: server-app\nlayer: action\nmax_lines_per_file: 250\nallowed_imports: [\"server/domain::*\", \"contracts::*\"]\nforbidden_imports: [\"client::*\"]\n---\n# ⚙️ Orchestration & Cas d'Usage\n\nServices applicatifs coordonnant le domaine et les adaptateurs.\n")),
        ("server/api", format!("---\nid: server-api\nlayer: action\nmax_lines_per_file: 250\nallowed_imports: [\"server/application::*\", \"contracts::*\"]\nforbidden_imports: [\"server/domain::*\"]\n---\n# 🌐 Entrées API & Contrôleurs RPC/WebSocket\n\nWHEN network packet received THE SYSTEM SHALL route through contracts schema.\n")),
        ("data-nodes", format!("---\nid: data-nodes\nlayer: database\nmax_lines_per_file: 300\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"client::*\"]\n---\n# 🗄️ Services & Nœuds de Données Dissociables\n\n> **Découplage :** {}\n", stack_db_note)),
        ("data-nodes/db-primary", format!("---\nid: db-primary\nlayer: database\nmax_lines_per_file: 250\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"client::*\"]\n---\n# 💾 Adaptateur Base de Données Primaire\n\nMigrations, modèles relationnels et persistance.\n")),
        ("data-nodes/cache-worker", format!("---\nid: cache-worker\nlayer: utility\nmax_lines_per_file: 200\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"client::*\"]\n---\n# ⚡ Cache & Tâches en Arrière-Plan\n\nFiles d'attente (Redis/MQ) et workers asynchrones isolables.\n")),
    ];

    let mut created = Vec::new();
    for (rel_dir, readme_content) in structure {
        let dir_path = base.join(rel_dir);
        let _ = fs::create_dir_all(&dir_path);
        let readme_path = dir_path.join("README.md");
        let _ = fs::write(&readme_path, readme_content);
        created.push(rel_dir.to_string());
    }

    // Calcule et scelle les hashes BLAKE3 de tous les README.md générés dans aether.lock.toml
    let _ = sign_project_contracts(base, None);

    // Fichier maître de directives IA optimisé AETHER_AI_RULES.md
    let rules_file = base.join("AETHER_AI_RULES.md");
    let rules_content = AuditWriter::generate_optimized_system_prompt(base, &proj_name, stack_str, 3030);
    let _ = fs::write(rules_file, rules_content);

    // Fichiers de code de démarrage avec documentation complète et style ultra-normé
    let code_files: Vec<(&str, &str)> = match stack {
        StackType::PureRust => vec![
            ("contracts/src/lib.rs", r#"//! # 📜 Contrats d'Interface & Schémas Partagés
//!
//! Contient les DTOs, les types de transfert et les ports d'abstraction.

use serde::{Deserialize, Serialize};

/// # [CONTRACT-001] Objet de transfert de données pour une réservation
///
/// ## Invariants
/// - `id` : Identifiant unique non vide
/// - `nights` : Nombre de nuitées (strictement > 0 et <= 90)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReservationDto {
    pub id: String,
    pub client_name: String,
    pub nights: u32,
    pub total_amount: u64,
}

/// # [PORT-001] Port d'accès abstrait au stockage (Découplage local/distant)
///
/// ## Spécification EARS
/// - **WHEN** l'application demande la persistance d'une réservation
/// - **THEN** l'adaptateur de données doit sauvegarder le DTO de manière atomique
pub trait RepositoryPort: Send + Sync {
    /// Sauvegarde une réservation dans le système de persistance actif
    fn save_reservation(&self, reservation: &ReservationDto) -> Result<(), String>;
    /// Récupère une réservation par son identifiant unique
    fn find_by_id(&self, id: &str) -> Result<Option<ReservationDto>, String>;
}
"#),
            ("server/domain/src/lib.rs", r#"//! # 🏛️ Couche Domaine Pur (Zéro I/O, 100% Déterministe)
//!
//! Règles métier fondamentales, calculs financiers et invariants stricts.

/// # [DOMAIN-001] Calcule le montant total d'un séjour avec application des taxes
///
/// ## Spécification EARS
/// - **WHEN** le nombre de nuits est strictement positif et inférieur ou égal à 90
/// - **THEN** le système calcule le montant brut majoré de la taxe de séjour (5%)
///
/// ## Invariants & Sécurité
/// - Fonction 100% pure, déterministe, sans effet de bord, sans I/O réseau ou disque.
/// - Complexité O(1).
///
/// ## Arguments
/// - `nights`: Nombre de nuitées (1..=90)
/// - `rate_per_night`: Tarif par nuit en centimes / wei
pub fn calculate_stay_cost(nights: u32, rate_per_night: u64) -> Result<u64, &'static str> {
    if nights == 0 {
        return Err("Le séjour doit comporter au moins 1 nuit.");
    }
    if nights > 90 {
        return Err("La durée maximale d'un séjour continu est de 90 nuits.");
    }
    let base = (nights as u64) * rate_per_night;
    let tax = base * 5 / 100;
    Ok(base + tax)
}
"#),
            ("server/application/src/lib.rs", r#"//! # ⚙️ Couche Orchestration Applicative (Cas d'Usage)
//!
//! Coordonne les flux entre le domaine pur et les adaptateurs d'infrastructure.

/// # [APP-001] Traite la création d'un dossier de réservation complet
///
/// ## Spécification EARS
/// - **WHEN** une demande utilisateur est validée par le contrat
/// - **THEN** le service applique les règles domaine et prépare l'enregistrement
pub fn process_reservation_usecase(client: &str, nights: u32, rate: u64) -> Result<u64, &'static str> {
    if client.trim().is_empty() {
        return Err("Nom de client invalide.");
    }
    let total = (nights as u64) * rate;
    Ok(total)
}
"#),
            ("server/api/src/lib.rs", r#"//! # 🌐 Entrées API & Contrôleurs RPC (Routes Réseau)
//!
//! Point de contact réseau scanné par AetherScope (Laser Orange RPC).

/// # [API-001] Point d'entrée de réservation HTTP POST /api/book
///
/// Reçoit la payload du formulaire client («Form»), la valide et l'achemine.
pub fn handle_post_book(payload: &str) -> String {
    format!("Booking route /api/book processed: {}", payload)
}
"#),
            ("client/ui/src/form.rs", r#"//! # 🎨 Formulaires et Rendu Visuel («Form»)

/// # [UI-001] Formulaire de réservation de chambre («Form»)
///
/// Stéréotype: «Form»
/// Soumet vers: `/api/book` (Connexion Laser Orange RPC)
pub fn render_booking_form(client_name: &str, nights: u32) {
    let _ = "fetch('/api/book')";
}
"#),
            ("data-nodes/db-primary/src/lib.rs", r#"//! # 💾 Adaptateur Base de Données Primaire (Repository SQLite / Postgres)

/// # [DB-001] Adaptateur de stockage primaire (SQLite local ou Postgres distant)
pub struct PrimaryDatabaseAdapter {
    pub connection_url: String,
}

impl PrimaryDatabaseAdapter {
    pub fn new(connection_url: &str) -> Self {
        Self { connection_url: connection_url.to_string() }
    }
}
"#),
        ],
        StackType::PurePythonUv => vec![
            ("contracts/schemas.py", r#""""📜 Contrats Pydantic v2 & Interfaces Partagées.

Valide de manière stricte tous les échanges entre le client, l'API et les data-nodes.
"""
from pydantic import BaseModel, Field

class BookingRequest(BaseModel):
    """[CONTRACT-001] Schéma de validation pour une demande de réservation."""
    client_name: str = Field(..., min_length=2, description="Nom complet du client")
    nights: int = Field(..., gt=0, le=90, description="Nombre de nuitées")
    rate_per_night: float = Field(default=120.0, gt=0, description="Tarif unitaire")

class BookingResponse(BaseModel):
    """[CONTRACT-002] Schéma de réponse après calcul du domaine."""
    booking_id: str
    total_amount: float
    status: str
"#),
            ("server/domain/models.py", r#""""🏛️ Couche Domaine Pur (Zéro I/O, 100% Déterministe)."""

def calculate_booking_total(nights: int, rate: float) -> float:
    """[DOMAIN-001] Calcule le montant total d'un séjour avec taxes légales.

    Spécification EARS:
        WHEN le nombre de nuitées est valide (1 à 90)
        THEN le système calcule le prix total avec 5% de taxe de séjour

    Invariants:
        Fonction 100% pure, déterministe, zéro I/O réseau ou base de données.

    Args:
        nights (int): Nombre de nuits (1-90).
        rate (float): Tarif par nuitée.

    Returns:
        float: Montant total calculé.
    """
    base = nights * rate
    return round(base * 1.05, 2)
"#),
            ("server/api/router.py", r#""""🌐 Entrées API & Contrôleurs FastAPI."""

def handle_booking_route(payload: dict) -> dict:
    """[API-001] Endpoint HTTP POST /api/book.
    
    Reçoit les entrées du formulaire client («Form») et valide via Pydantic.
    """
    return {"status": "confirmed", "route": "/api/book"}
"#),
            ("client/ui/form.py", r#""""🎨 Formulaire Client («Form»)."""

def render_booking_form():
    """[UI-001] Composant Formulaire client.
    Soumet vers: /api/book (Laser Orange RPC)
    """
    url = "/api/book"
    return f"fetch('{url}')"
"#),
        ],
        StackType::PureNodePnpm => vec![
            ("contracts/index.ts", r#"import { z } from 'zod';

/**
 * [CONTRACT-001] Schéma Zod de validation de réservation hôtelière
 */
export const BookingSchema = z.object({
  clientName: z.string().min(2),
  nights: z.number().int().positive().max(90),
  ratePerNight: z.number().positive().default(120),
});

export type BookingInput = z.infer<typeof BookingSchema>;
"#),
            ("server/domain/pricing.ts", r#"/**
 * [DOMAIN-001] Calcule le coût global d'une réservation.
 *
 * @remarks
 * Spécification EARS:
 * - WHEN les entrées sont validées par BookingSchema
 * - THEN le domaine applique la taxe de séjour de 5%
 *
 * @param nights - Nombre de nuitées strictement positif
 * @param rate - Tarif unitaire unifié
 * @returns Montant total calculé
 */
export function computeStayTotal(nights: number, rate: number): number {
  const base = nights * rate;
  return Math.round(base * 1.05 * 100) / 100;
}
"#),
            ("server/api/routes.ts", r#"/**
 * [API-001] Handler HTTP POST /api/book
 * Route déclarée reliant le formulaire client («Form»).
 */
export async function handleBookingApi(req: any) {
  return { status: 'confirmed', route: '/api/book' };
}
"#),
            ("client/ui/BookingForm.tsx", r#"/**
 * [UI-001] Formulaire de réservation («Form»)
 * Cible: fetch('/api/book') -> Laser Orange RPC
 */
export function BookingForm() {
  const submit = () => fetch('/api/book');
  return null;
}
"#),
        ],
        StackType::HybridMmoWeb3 => vec![
            ("contracts/packets.rs", r#"//! # 📜 Définitions des Paquets WebSocket & ABIs Web3

/// # [WS-001] Paquet émis par le client joueur
#[derive(Debug, Clone)]
pub struct ClientPacketMove {
    pub player_id: String,
    pub x: f32,
    pub y: f32,
}

/// # [WS-002] Paquet d'état synchronisé par le serveur
#[derive(Debug, Clone)]
pub struct ServerPacketStateUpdate {
    pub tick: u64,
    pub entities_count: usize,
}
"#),
            ("server/domain/world.rs", r#"//! # 🏛️ Moteur de Monde & Simulation Stellaire MMO (Pur)

/// # [DOMAIN-001] Met à jour la position spatiale d'une entité
///
/// ## Spécification EARS
/// - **WHEN** un paquet de mouvement arrive dans le tick actif
/// - **THEN** le système valide les collisions et met à jour les coordonnées
pub fn update_player_coord(current: f32, delta: f32) -> f32 {
    current + delta
}
"#),
            ("server/api/websocket.rs", r#"//! # ⚡ Contrôleur WebSocket & Dispatch de Paquets

/// # [WS-ROUTE-001] Router de paquets WebSocket temps réel
pub fn handle_client_packet(packet: &str) -> String {
    format!("ServerPacket::StateUpdate for {}", packet)
}
"#),
            ("client/ui/GameCanvas.ts", r#"/**
 * [UI-001] Rendu Canvas 2D/WebGL PixiJS («Form» & Realtime)
 * Émet vers: socket.emit('ClientPacket::Move')
 */
export class GameCanvas {
  sendMove(x: number, y: number) {
    // socket.emit('ClientPacket::Move')
  }
}
"#),
        ],
        StackType::RobloxLuau => vec![
            ("contracts/NetworkContracts.luau", r#"--!strict
--[[
  📜 [CONTRACT-ROBLOX-001] Spécification des Remotes Réseau & Protocoles Partagés
  Architecture optimisée pour Aether Code — Zero-Trust Client
]]

export type NetworkRemoteSpec = {
    name: string,
    kind: "RemoteEvent" | "RemoteFunction",
    rateLimitHz: number,
    requiresAuth: boolean,
}

local NetworkContracts = {
    REMOTES = {
        PlayerAction = "PlayerActionRemote" :: string,
        CombatCast = "CombatCastRemote" :: string,
        RequestInventorySync = "RequestInventorySyncFunction" :: string,
    },
    LIMITS = {
        MAX_ACTIONS_PER_SECOND = 20,
        MAX_CAST_RANGE_STUDS = 60,
    }
}

return NetworkContracts
"#),
            ("contracts/Types.luau", r#"--!strict
--[[
  📜 [TYPES-ROBLOX-001] Invariants et Types de Données Partagés
  Validation EARS des entités de jeu
]]

export type PlayerId = number

export type InventoryItem = {
    id: string,
    name: string,
    count: number,
    rarity: "Common" | "Rare" | "Epic" | "Legendary",
}

export type PlayerSessionData = {
    userId: PlayerId,
    username: string,
    level: number,
    experience: number,
    coins: number,
    inventory: { [string]: InventoryItem },
    lastSavedTimestamp: number,
}

export type ActionPayload = {
    actionType: "Attack" | "Interact" | "UseSkill",
    targetId: string?,
    clientTimestamp: number,
}

local Types = {}
return Types
"#),
            ("server/ServerController.luau", r#"--!strict
--[[
  ⚡ [SERVER-001] Authoritative Game Engine Loop
  - WHEN client sends action THEN the server evaluates invariants authoritatively
  - ZERO TRUST : Never trust position, velocity or damage claimed by client
]]

local Players = game:GetService("Players")

local ServerController = {}
ServerController.__index = ServerController

function ServerController.Init()
    print("🎮 [AETHER ROBLOX SERVER] Initialisation du moteur authoritative...")
    
    Players.PlayerAdded:Connect(function(player: Player)
        print(string.format("🟢 Joueur connecté : %s (%d)", player.Name, player.UserId))
    end)
    
    Players.PlayerRemoving:Connect(function(player: Player)
        print(string.format("🔴 Joueur déconnecté : %s (%d)", player.Name, player.UserId))
    end)
end

return ServerController
"#),
            ("server/domain/CombatService.luau", r#"--!strict
--[[
  🏛️ [DOMAIN-001] Logique de Combat & Validation Anti-Cheat (Pure)
  100% authoritative côté serveur, zéro effet de bord UI
]]

local CombatService = {}

function CombatService.ValidateCast(playerPos: Vector3, targetPos: Vector3, maxRange: number): (boolean, string?)
    local distance = (playerPos - targetPos).Magnitude
    if distance > maxRange then
        return false, string.format("Portée dépassée: %.1f > %.1f", distance, maxRange)
    end
    return true, nil
end

function CombatService.CalculateDamage(baseDmg: number, defense: number): number
    local reduction = math.clamp(defense / (defense + 100), 0, 0.75)
    return math.max(1, math.floor(baseDmg * (1 - reduction)))
end

return CombatService
"#),
            ("client/ClientController.luau", r#"--!strict
--[[
  💻 [CLIENT-001] Contrôleur Joueur Local & Prédiction Visuelle
  Rendu uniquement, zéro autorité sur l'état global du monde
]]

local Players = game:GetService("Players")
local localPlayer = Players.LocalPlayer

local ClientController = {}

function ClientController.Init()
    print("🕹️ [AETHER CLIENT] Contrôleur joueur initialisé pour " .. localPlayer.Name)
end

return ClientController
"#),
            ("data-nodes/DataStoreServiceAdapter.luau", r#"--!strict
--[[
  🗄️ [DATASTORE-001] Adaptateur de Persistance DataStore avec Session-Locking
  Pattern ProfileService anti-dupe et tolérance aux pannes réseau
]]

local DataStoreService = game:GetService("DataStoreService")
local playerDataStore = DataStoreService:GetDataStore("AetherPlayerStore_v1")

local DataStoreAdapter = {}

function DataStoreAdapter.LoadProfile(userId: number): any
    local key = "Player_" .. tostring(userId)
    local success, result = pcall(function()
        return playerDataStore:GetAsync(key)
    end)
    if not success then
        warn("❌ Erreur lecture DataStore pour " .. key .. ": " .. tostring(result))
        return nil
    end
    return result
end

function DataStoreAdapter.SaveProfile(userId: number, data: any): boolean
    local key = "Player_" .. tostring(userId)
    local success, err = pcall(function()
        playerDataStore:SetAsync(key, data)
    end)
    if not success then
        warn("❌ Erreur écriture DataStore pour " .. key .. ": " .. tostring(err))
        return false
    end
    return true
end

return DataStoreAdapter
"#),
            ("default.project.json", r#"{
  "name": "AetherRobloxServer",
  "tree": {
    "$className": "DataModel",
    "ReplicatedStorage": {
      "$className": "ReplicatedStorage",
      "Contracts": {
        "$path": "contracts"
      }
    },
    "ServerScriptService": {
      "$className": "ServerScriptService",
      "Server": {
        "$path": "server"
      }
    },
    "StarterPlayer": {
      "$className": "StarterPlayer",
      "StarterPlayerScripts": {
        "$className": "StarterPlayerScripts",
        "Client": {
          "$path": "client"
        }
      }
    },
    "ServerStorage": {
      "$className": "ServerStorage",
      "DataNodes": {
        "$path": "data-nodes"
      }
    }
  }
}
"#),
            ("wally.toml", r#"[package]
name = "aether/roblox-server"
version = "0.1.0"
registry = "https://github.com/Upturn/wally-index"
realm = "shared"

[dependencies]
# Promise = "evaera/promise@4.0.0"
# Signal = "sleitnick/signal@2.0.1"
"#),
            ("selene.toml", r#"std = "roblox"

[rules]
empty_if = "warn"
multiple_statements = "warn"
shadowing = "warn"
unused_variable = "warn"
"#),
        ],
        StackType::MinecraftServer => vec![
            ("contracts/AETHER_MC_MANIFEST_SPEC.md", r#"# 📜 Spécification Manifest Serveur Minecraft Aether

## 🛡️ Invariants EARS
- WHEN server boots THE RUNNER SHALL apply Aikar JVM garbage collection flags.
- WHEN control plane requests state THE RUNNER SHALL emit JSON heartbeat over IPC.
- WHEN plugin triggers event THE HANDLER SHALL process asynchronously without blocking main tick.
"#),
            ("server/server.properties", r#"# Minecraft Server Properties - Aether Engine Optimized
server-port=25565
online-mode=true
enable-rcon=false
difficulty=normal
gamemode=survival
max-players=50
view-distance=10
simulation-distance=8
network-compression-threshold=256
"#),
            ("server/start.bat", r#"@echo off
title Aether Minecraft Game Server
java -Xms4G -Xmx4G -XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200 -XX:+UnlockExperimentalVMOptions -XX:+DisableExplicitGC -XX:+AlwaysPreTouch -XX:G1NewSizePercent=30 -XX:G1MaxNewSizePercent=40 -XX:G1ReservePercent=20 -XX:G1HeapWastePercent=5 -XX:G1MixedGCCountTarget=4 -XX:InitiatingHeapOccupancyPercent=15 -XX:G1MixedGCLiveThresholdPercent=90 -XX:G1RSetUpdatingPauseTimePercent=5 -XX:SurvivorRatio=32 -XX:+PerfDisableSharedMem -XX:MaxTenuringThreshold=1 -Dusing.aikars.flags=https://mcflags.emc.gs -Daikars.new.flags=true -jar paper.jar nogui
pause
"#),
            ("server/start.sh", r#"#!/usr/bin/env bash
# Aether Minecraft Game Server Runner
exec java -Xms4G -Xmx4G -XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200 -XX:+UnlockExperimentalVMOptions -XX:+DisableExplicitGC -XX:+AlwaysPreTouch -XX:G1NewSizePercent=30 -XX:G1MaxNewSizePercent=40 -XX:G1ReservePercent=20 -XX:G1HeapWastePercent=5 -XX:G1MixedGCCountTarget=4 -XX:InitiatingHeapOccupancyPercent=15 -XX:G1MixedGCLiveThresholdPercent=90 -XX:G1RSetUpdatingPauseTimePercent=5 -XX:SurvivorRatio=32 -XX:+PerfDisableSharedMem -XX:MaxTenuringThreshold=1 -Dusing.aikars.flags=https://mcflags.emc.gs -Daikars.new.flags=true -jar paper.jar nogui
"#),
            ("server/paper-global.yml", r#"# Paper Global Config - High Concurrency Tuning
timings:
  enabled: true
  verbose: false
chunk-loading:
  min-load-radius: 2
  max-concurrent-sends: 2
watchdog:
  early-warning-every: 5000
  early-warning-delay: 10000
"#),
            ("plugins/README.md", r#"# 📦 Plugins Serveur Minecraft
Placez vos plugins Paper/Purpur (.jar) dans ce dossier.
Recommandations Aether : LuckPerms, Chunky, FastAsyncWorldEdit, ProtocolLib.
"#),
        ],
        StackType::ClassicMvc => vec![
            ("models/README.md", r#"# 🗄️ Modèles & Entités (M)
Couche de données et de domaine représentant les entités métier, les schémas DTO et la persistance.
- WHEN model is loaded THE SYSTEM SHALL enforce type safety and constraints.
"#),
            ("views/README.md", r#"# 💻 Vues & Composants (V)
Rendu d'interface, formulaires utilisateur et templates.
- WHEN view renders data THE SYSTEM SHALL escape dynamic values.
- View SHALL NOT directly import or query models or database.
"#),
            ("controllers/README.md", r#"# ⚡ Contrôleurs d'Action (C)
Points d'entrée des requêtes, dispatching d'actions et coordination.
- WHEN controller receives request THE SYSTEM SHALL validate inputs before calling services.
"#),
            ("services/README.md", r#"# 🏛️ Services Métier
Logique métier pure et orchestration des flux entre modèles et contrôleurs.
"#),
        ],
    };

    for (rel_file, file_content) in code_files {
        let fpath = base.join(rel_file);
        if let Some(parent) = fpath.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&fpath, file_content);
    }

    created
}

pub fn pick_folder_dialog(title: &str) -> Option<PathBuf> {
    // 1. Essai avec rfd
    if let Some(folder) = rfd::FileDialog::new().set_title(title).pick_folder() {
        return Some(folder);
    }

    // 2. Fallback garanti sur Windows via System.Windows.Forms
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let ps_cmd = format!(
            r#"Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.FolderBrowserDialog; $f.Description = '{}'; $f.ShowNewFolderButton = $true; if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {{ Write-Output $f.SelectedPath }}"#,
            title
        );
        let mut cmd = std::process::Command::new("powershell");
        cmd.args(["-NoProfile", "-Command", &ps_cmd]);
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW

        if let Ok(output) = cmd.output() {
            if output.status.success() {
                let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path_str.is_empty() && Path::new(&path_str).is_dir() {
                    return Some(PathBuf::from(path_str));
                }
            }
        }
    }
    None
}

/// Inspecte le statut Git du projet en exécutant `git status --porcelain=v1 -uall --ignored=no`
/// et croise les fichiers modifiés / non suivis avec les bulles du graphe AetherGraph pour
/// détecter les violations de sécurité SAST CWE et les ruptures de contrats EARS.
pub fn inspect_git_status(project_root: &Path, graph: &AetherGraph) -> GitStatusResponse {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["status", "--porcelain=v1", "-uall", "--ignored=no"])
        .current_dir(project_root);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }

    let output = match cmd.output() {
        Ok(out) if out.status.success() => out,
        _ => {
            return GitStatusResponse {
                is_git_repo: false,
                branch: None,
                clean: true,
                files: Vec::new(),
                modified_count: 0,
                untracked_count: 0,
                staged_count: 0,
                deleted_count: 0,
                security_alert_count: 0,
            };
        }
    };

    let mut branch_cmd = std::process::Command::new("git");
    branch_cmd
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(project_root);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        branch_cmd.creation_flags(0x08000000);
    }

    let branch = branch_cmd
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if s.is_empty() { None } else { Some(s) }
            } else {
                None
            }
        });

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    parse_git_status_porcelain(&stdout_str, branch, true, graph)
}

/// Analyse la sortie porcelain v1 de Git et effectue la corrélation avec l'AetherGraph.
pub fn parse_git_status_porcelain(
    stdout_str: &str,
    branch: Option<String>,
    is_git_repo: bool,
    graph: &AetherGraph,
) -> GitStatusResponse {
    let mut files = Vec::new();
    let mut modified_count = 0;
    let mut untracked_count = 0;
    let mut staged_count = 0;
    let mut deleted_count = 0;
    let mut security_alert_count = 0;

    for line in stdout_str.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }
        if line.len() < 3 {
            continue;
        }
        let mut chars = line.chars();
        let index_code = chars.next().unwrap_or(' ');
        let worktree_code = chars.next().unwrap_or(' ');
        if index_code == '#' || (index_code == ' ' && worktree_code == ' ') {
            continue;
        }
        let raw_path = if line.len() >= 3 && line.as_bytes()[2] == b' ' {
            &line[3..]
        } else {
            let _ = chars.next();
            chars.as_str()
        };

        let trimmed_raw = raw_path.trim();
        let unquoted = if trimmed_raw.starts_with('"') && trimmed_raw.ends_with('"') && trimmed_raw.len() >= 2 {
            &trimmed_raw[1..trimmed_raw.len() - 1]
        } else {
            trimmed_raw
        };

        let target_part = unquoted.split(" -> ").last().unwrap_or(unquoted).trim_matches('"');
        let file_path = target_part
            .trim_start_matches("./")
            .replace('\\', "/");

        if file_path.trim().is_empty() {
            continue;
        }

        let status = match (index_code, worktree_code) {
            ('U', _) | (_, 'U') | ('A', 'A') | ('D', 'D') => {
                modified_count += 1;
                GitFileStatusKind::Conflict
            }
            ('?', '?') => {
                untracked_count += 1;
                GitFileStatusKind::Untracked
            }
            ('D', _) | (_, 'D') => {
                deleted_count += 1;
                GitFileStatusKind::Deleted
            }
            ('R', _) => {
                staged_count += 1;
                GitFileStatusKind::Renamed
            }
            ('A', ' ') | ('M', ' ') | ('C', ' ') => {
                staged_count += 1;
                GitFileStatusKind::Staged
            }
            _ => {
                modified_count += 1;
                GitFileStatusKind::Modified
            }
        };

        // Corrélation avec les alertes SAST et contrats EARS du graphe
        let mut has_sec = false;
        let mut cwe_count = 0;
        let mut ears_violation = false;
        let mut max_severity: Option<String> = None;

        for node in &graph.nodes {
            let node_path = node.file_path.trim_start_matches("./").replace('\\', "/");
            if node_path == file_path {
                if node.has_security_violation {
                    has_sec = true;
                }
                cwe_count += node
                    .metadata
                    .cve_anomalies
                    .iter()
                    .filter(|a| {
                        a.rule_id != "RULE_MAX_LINES"
                            && !a.cve_id.contains("ARCH-BUDGET-EXCEEDED")
                            && a.severity != "WARNING"
                    })
                    .count();
                for anomaly in &node.metadata.cve_anomalies {
                    let sev = anomaly.severity.to_uppercase();
                    if sev == "CRITICAL" {
                        max_severity = Some("CRITICAL".to_string());
                    } else if sev == "HIGH" && max_severity.as_deref() != Some("CRITICAL") {
                        max_severity = Some("HIGH".to_string());
                    } else if (sev == "MEDIUM" || sev == "WARNING")
                        && (max_severity.is_none()
                            || max_severity.as_deref() == Some("LOW")
                            || max_severity.as_deref() == Some("INFO"))
                    {
                        max_severity = Some(sev);
                    } else if max_severity.is_none() {
                        max_severity = Some(sev);
                    }
                }
                for v in &node.metadata.violations {
                    if v.contains("RULE_MAX_LINES") || v.contains("ARCH-BUDGET-EXCEEDED") {
                        continue;
                    }
                    if v.contains("RULE_FORBIDDEN_IMPORT")
                        || v.contains("BLAKE3_TAMPERED")
                        || !v.is_empty()
                    {
                        ears_violation = true;
                        has_sec = true;
                    }
                }
            }
        }

        if cwe_count > 0 {
            has_sec = true;
        }

        if has_sec || ears_violation {
            security_alert_count += 1;
        }

        files.push(GitFileChange {
            path: file_path,
            status,
            index_code,
            worktree_code,
            has_security_violation: has_sec,
            cwe_count,
            ears_violation,
            max_severity,
        });
    }

    let clean = files.is_empty();

    GitStatusResponse {
        is_git_repo,
        branch,
        clean,
        files,
        modified_count,
        untracked_count,
        staged_count,
        deleted_count,
        security_alert_count,
    }
}

#[cfg(test)]
mod git_status_tests {
    use super::*;
    use core_graph::bubble::{CveAnomalyRecord, SymbolBubble, SymbolKind};

    #[test]
    fn test_parse_git_status_porcelain_clean() {
        let graph = AetherGraph::new("TestProject");
        let resp = parse_git_status_porcelain("", Some("main".to_string()), true, &graph);
        assert!(resp.is_git_repo);
        assert_eq!(resp.branch.as_deref(), Some("main"));
        assert!(resp.clean);
        assert!(resp.files.is_empty());
        assert_eq!(resp.modified_count, 0);
        assert_eq!(resp.untracked_count, 0);
        assert_eq!(resp.staged_count, 0);
        assert_eq!(resp.deleted_count, 0);
        assert_eq!(resp.security_alert_count, 0);
    }

    #[test]
    fn test_parse_git_status_porcelain_various_statuses() {
        let graph = AetherGraph::new("TestProject");
        let porcelain = [
            " M crates/desktop-shell/src/viewer.rs",
            "M  crates/desktop-shell/src/main.rs",
            "?? new_untracked_file.rs",
            " D deleted_worktree.rs",
            "D  deleted_staged.rs",
            "R  old_name.rs -> new_name.rs",
            "UU conflicted_merge.rs",
        ].join("\n");
        let resp = parse_git_status_porcelain(&porcelain, Some("feature/diff".to_string()), true, &graph);
        assert!(resp.is_git_repo);
        assert_eq!(resp.branch.as_deref(), Some("feature/diff"));
        assert!(!resp.clean);
        assert_eq!(resp.files.len(), 7);

        assert_eq!(resp.files[0].path, "crates/desktop-shell/src/viewer.rs");
        assert_eq!(resp.files[0].status, GitFileStatusKind::Modified);
        assert_eq!(resp.files[0].index_code, ' ');
        assert_eq!(resp.files[0].worktree_code, 'M');

        assert_eq!(resp.files[1].path, "crates/desktop-shell/src/main.rs");
        assert_eq!(resp.files[1].status, GitFileStatusKind::Staged);
        assert_eq!(resp.files[1].index_code, 'M');
        assert_eq!(resp.files[1].worktree_code, ' ');

        assert_eq!(resp.files[2].path, "new_untracked_file.rs");
        assert_eq!(resp.files[2].status, GitFileStatusKind::Untracked);

        assert_eq!(resp.files[3].path, "deleted_worktree.rs");
        assert_eq!(resp.files[3].status, GitFileStatusKind::Deleted);

        assert_eq!(resp.files[4].path, "deleted_staged.rs");
        assert_eq!(resp.files[4].status, GitFileStatusKind::Deleted);

        assert_eq!(resp.files[5].path, "new_name.rs");
        assert_eq!(resp.files[5].status, GitFileStatusKind::Renamed);

        assert_eq!(resp.files[6].path, "conflicted_merge.rs");
        assert_eq!(resp.files[6].status, GitFileStatusKind::Conflict);

        assert_eq!(resp.modified_count, 2);
        assert_eq!(resp.untracked_count, 1);
        assert_eq!(resp.staged_count, 2);
        assert_eq!(resp.deleted_count, 2);
        assert_eq!(resp.security_alert_count, 0);
    }

    #[test]
    fn test_parse_git_status_porcelain_security_and_ears_cross_reference() {
        let mut graph = AetherGraph::new("TestProject");

        // Safe node
        let safe_node = SymbolBubble::new(
            "file::safe.rs".to_string(),
            "safe.rs".to_string(),
            "safe.rs".to_string(),
            1,
            SymbolKind::File,
            "server".to_string(),
            "domain".to_string(),
        );
        graph.nodes.push(safe_node);

        // Vulnerable node with CRITICAL anomaly
        let mut vuln_node = SymbolBubble::new(
            "file::vuln.rs".to_string(),
            "vuln.rs".to_string(),
            "vuln.rs".to_string(),
            1,
            SymbolKind::File,
            "server".to_string(),
            "domain".to_string(),
        );
        vuln_node.has_security_violation = true;
        vuln_node.metadata.cve_anomalies.push(CveAnomalyRecord {
            rule_id: "RULE_SQL_INJECTION".to_string(),
            cve_id: "CWE-89".to_string(),
            severity: "HIGH".to_string(),
            line_number: 10,
            file_path: "vuln.rs".to_string(),
            message: "SQL Injection vulnerability".to_string(),
            ..Default::default()
        });
        vuln_node.metadata.cve_anomalies.push(CveAnomalyRecord {
            rule_id: "RULE_COMMAND_INJECTION".to_string(),
            cve_id: "CWE-78".to_string(),
            severity: "CRITICAL".to_string(),
            line_number: 25,
            file_path: "vuln.rs".to_string(),
            message: "Command Injection vulnerability".to_string(),
            ..Default::default()
        });
        graph.nodes.push(vuln_node);

        // EARS contract violation node
        let mut ears_node = SymbolBubble::new(
            "file::ears_fail.rs".to_string(),
            "ears_fail.rs".to_string(),
            "ears_fail.rs".to_string(),
            1,
            SymbolKind::File,
            "server".to_string(),
            "domain".to_string(),
        );
        ears_node.metadata.violations.push("RULE_FORBIDDEN_IMPORT: forbidden import found".to_string());
        graph.nodes.push(ears_node);

        let porcelain = " M safe.rs\n M vuln.rs\n M ears_fail.rs\n";
        let resp = parse_git_status_porcelain(porcelain, Some("main".to_string()), true, &graph);
        assert_eq!(resp.files.len(), 3);

        // Safe file
        assert_eq!(resp.files[0].path, "safe.rs");
        assert!(!resp.files[0].has_security_violation);
        assert_eq!(resp.files[0].cwe_count, 0);
        assert!(!resp.files[0].ears_violation);
        assert_eq!(resp.files[0].max_severity, None);

        // Vuln file
        assert_eq!(resp.files[1].path, "vuln.rs");
        assert!(resp.files[1].has_security_violation);
        assert_eq!(resp.files[1].cwe_count, 2);
        assert!(!resp.files[1].ears_violation);
        assert_eq!(resp.files[1].max_severity.as_deref(), Some("CRITICAL"));

        // EARS violation file
        assert_eq!(resp.files[2].path, "ears_fail.rs");
        assert!(resp.files[2].has_security_violation);
        assert_eq!(resp.files[2].cwe_count, 0);
        assert!(resp.files[2].ears_violation);

        assert_eq!(resp.security_alert_count, 2);
    }

    #[test]
    fn test_parse_git_status_porcelain_windows_paths_and_quotes() {
        let graph = AetherGraph::new("TestProject");
        let porcelain = " M \"crates\\sub folder\\file.rs\"\n";
        let resp = parse_git_status_porcelain(porcelain, None, true, &graph);
        assert_eq!(resp.files.len(), 1);
        assert_eq!(resp.files[0].path, "crates/sub folder/file.rs");
        assert_eq!(resp.files[0].status, GitFileStatusKind::Modified);
    }

    #[test]
    fn test_parse_git_status_porcelain_whitespace_and_branch_headers() {
        let graph = AetherGraph::new("TestProject");
        let porcelain = "## main\n   \n\t\n# comment\n M valid.rs\n";
        let resp = parse_git_status_porcelain(porcelain, Some("main".to_string()), true, &graph);
        assert_eq!(resp.files.len(), 1);
        assert_eq!(resp.files[0].path, "valid.rs");
        assert_eq!(resp.files[0].status, GitFileStatusKind::Modified);
        assert_eq!(resp.modified_count, 1);
    }

    #[test]
    fn test_inspect_git_status_non_git_repo() {
        let temp_dir = std::env::temp_dir().join(format!("aether_non_git_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let graph = AetherGraph::new("NonGitProject");

        let resp = inspect_git_status(&temp_dir, &graph);
        assert!(!resp.is_git_repo);
        assert!(resp.clean);
        assert!(resp.files.is_empty());
        assert_eq!(resp.modified_count, 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}

#[cfg(test)]
mod app_state_tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_app_state_initialization_pure_code() {
        let dummy_graph = AetherGraph::new("CodeProject");
        let state = AppState::new(
            dummy_graph.clone(),
            PathBuf::from("/test/code"),
            DetectedProjectType::PureCode,
            "code".to_string(),
            Some(dummy_graph),
            None,
            None,
        );

        assert_eq!(state.get_project_type().await, DetectedProjectType::PureCode);
        assert_eq!(state.get_active_view_mode().await, "code");
        assert_eq!(state.get_supported_views().await, vec!["code"]);
        assert!(state.get_code_graph().await.is_some());
        assert!(state.get_vault_graph().await.is_none());
        assert_eq!(state.get_active_graph().await.project_name, "CodeProject");
    }

    #[tokio::test]
    async fn test_app_state_initialization_pure_vault() {
        let dummy_vault = AetherGraph::new("ObsidianVault");
        let state = AppState::new(
            dummy_vault.clone(),
            PathBuf::from("/test/vault"),
            DetectedProjectType::PureObsidianVault,
            "vault".to_string(),
            None,
            Some(dummy_vault),
            None,
        );

        assert_eq!(state.get_project_type().await, DetectedProjectType::PureObsidianVault);
        assert_eq!(state.get_active_view_mode().await, "vault");
        assert!(state.get_supported_views().await.contains(&"vault".to_string()));
        assert!(state.get_vault_graph().await.is_some());
        assert_eq!(state.get_active_graph().await.project_name, "ObsidianVault");
    }

    #[tokio::test]
    async fn test_app_state_mixed_dual_vision_toggle() {
        let code_g = AetherGraph::new("CodeGraph");
        let vault_g = AetherGraph::new("VaultGraph");
        let state = AppState::new(
            code_g.clone(),
            PathBuf::from("/test/mixed"),
            DetectedProjectType::Mixed,
            "code".to_string(),
            Some(code_g),
            Some(vault_g),
            None,
        );

        // Initial view
        assert_eq!(state.get_active_view_mode().await, "code");
        assert_eq!(state.get_active_graph().await.project_name, "CodeGraph");
        let v1 = state.graph_version.load(std::sync::atomic::Ordering::SeqCst);

        // Toggle to vault
        let swapped = state.switch_view_mode("vault").await.expect("Switch to vault should succeed");
        assert_eq!(swapped.project_name, "VaultGraph");
        assert_eq!(state.get_active_view_mode().await, "vault");
        assert_eq!(state.get_active_graph().await.project_name, "VaultGraph");
        let v2 = state.graph_version.load(std::sync::atomic::Ordering::SeqCst);
        assert!(v2 > v1);

        // Toggle back to code
        let back = state.switch_view_mode("code").await.expect("Switch to code should succeed");
        assert_eq!(back.project_name, "CodeGraph");
        assert_eq!(state.get_active_view_mode().await, "code");
        assert_eq!(state.get_active_graph().await.project_name, "CodeGraph");
        let v3 = state.graph_version.load(std::sync::atomic::Ordering::SeqCst);
        assert!(v3 > v2);
    }

    #[tokio::test]
    async fn test_app_state_alias_notes_maps_to_vault() {
        let code_g = AetherGraph::new("CodeGraph");
        let vault_g = AetherGraph::new("VaultGraph");
        let state = AppState::new(
            code_g.clone(),
            PathBuf::from("/test/mixed"),
            DetectedProjectType::Mixed,
            "code".to_string(),
            Some(code_g),
            Some(vault_g),
            None,
        );

        // Pass alias "notes"
        let res = state.switch_view_mode("notes").await.expect("Alias 'notes' should succeed");
        assert_eq!(res.project_name, "VaultGraph");
        assert_eq!(state.get_active_view_mode().await, "vault");
    }

    #[tokio::test]
    async fn test_app_state_unsupported_mode_rejection() {
        let code_g = AetherGraph::new("CodeGraph");
        let state = AppState::new(
            code_g.clone(),
            PathBuf::from("/test/code"),
            DetectedProjectType::PureCode,
            "code".to_string(),
            Some(code_g),
            None,
            None,
        );

        // PureCode does not have vault graph and scanning fails
        let err = state.switch_view_mode("vault").await.expect_err("Should fail");
        assert!(matches!(err, ViewModeError::GraphNotAvailable(_)));

        // Invalid mode
        let err_inv = state.switch_view_mode("galaxy").await.expect_err("Should fail");
        assert!(matches!(err_inv, ViewModeError::InvalidMode(_)));
    }

    #[tokio::test]
    async fn test_app_state_concurrent_access_stress() {
        let code_g = AetherGraph::new("CodeGraph");
        let vault_g = AetherGraph::new("VaultGraph");
        let state = Arc::new(AppState::new(
            code_g.clone(),
            PathBuf::from("/test/mixed"),
            DetectedProjectType::Mixed,
            "code".to_string(),
            Some(code_g),
            Some(vault_g),
            None,
        ));

        let mut handles = Vec::new();
        // Spawn 30 readers
        for _ in 0..30 {
            let s = state.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..50 {
                    let _ = s.get_active_graph().await;
                    let _ = s.get_active_view_mode().await;
                    let _ = s.get_project_status().await;
                }
            }));
        }

        // Spawn 10 togglers
        for i in 0..10 {
            let s = state.clone();
            handles.push(tokio::spawn(async move {
                for j in 0..20 {
                    let mode = if (i + j) % 2 == 0 { "code" } else { "vault" };
                    let _ = s.switch_view_mode(mode).await;
                }
            }));
        }

        for h in handles {
            h.await.expect("Task failed");
        }

        // Verify final state is valid
        let final_mode = state.get_active_view_mode().await;
        assert!(final_mode == "code" || final_mode == "vault");
        let final_graph = state.get_active_graph().await;
        assert!(final_graph.project_name == "CodeGraph" || final_graph.project_name == "VaultGraph");
    }
}

