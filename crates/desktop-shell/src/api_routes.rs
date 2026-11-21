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
    DetectedProjectType, PathGuard, ProjectDetectionReport, SecurityError,
};
use security_linter::SecretGuard;
use walkdir::WalkDir;

static ATOMIC_WRITE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_alerts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_cwe_bubbles: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_cwe_titles: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_folder_titles: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_file_titles: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_memory_mode: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_visual_plugin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_settings: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rescan: Option<bool>,
}

/// Transport compact du graphe vers l'UI (gros projets type PrestaShop : 40k noeuds / 250k aretes).
///
/// - Les aretes passent en tableaux d'entiers (indices de noeuds) + tables de relations :
///   ~78 Mo de JSON d'aretes -> ~4 Mo, et l'UI ne duplique plus 500k chaines d'identifiants.
/// - Les champs lourds des noeuds sont allégés (docstrings, hash, appels de méthodes) ;
///   le code complet reste chargé à la demande (`/api/file_content`).
/// - Les petits graphes gardent le format JSON historique (démo statique, tests, MCP `?full=1`).
pub mod ui_payload {
    use core_graph::graph::AetherGraph;
    use serde::{Serialize, Serializer};
    use std::collections::HashMap;

    pub const COMPACT_NODE_THRESHOLD: usize = 3_000;
    pub const COMPACT_EDGE_THRESHOLD: usize = 20_000;

    pub fn needs_compaction(g: &AetherGraph) -> bool {
        g.nodes.len() > COMPACT_NODE_THRESHOLD || g.edges.len() > COMPACT_EDGE_THRESHOLD
    }

    #[derive(Serialize, Default)]
    pub struct CompactEdgeExtra {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cve_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub severity: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub transmitted_data: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub transmitted_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub violation_details: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub label: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub weight: Option<f32>,
    }

    #[derive(Serialize)]
    pub struct CompactEdges {
        /// Extrémités d'arêtes qui ne sont pas des noeuds (index >= nodes.len()).
        pub ids: Vec<String>,
        pub rels: Vec<String>,
        pub types: Vec<String>,
        pub src: Vec<u32>,
        pub dst: Vec<u32>,
        pub rel: Vec<u16>,
        pub typ: Vec<u16>,
        /// Données rares (violations, taint) indexées par position d'arête.
        pub extra: HashMap<u32, CompactEdgeExtra>,
    }

    #[derive(Serialize)]
    pub struct UiGraphPayload {
        #[serde(flatten)]
        pub graph: AetherGraph,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub edges_compact: Option<CompactEdges>,
    }

    fn trunc(s: &mut String, max: usize) {
        if s.len() > max {
            let mut cut = max;
            while cut > 0 && !s.is_char_boundary(cut) {
                cut -= 1;
            }
            s.truncate(cut);
            s.push('…');
        }
    }

    pub fn build_payload(g: &AetherGraph) -> UiGraphPayload {
        let compact = needs_compaction(g);
        let mut nodes = g.nodes.clone();
        for n in nodes.iter_mut() {
            n.metadata.raw_content = None;
            if !n.metadata.cve_anomalies.is_empty() {
                n.metadata.violations.clear();
            }
            if compact {
                trunc(&mut n.docstring, 240);
                if let Some(h) = n.metadata.blake3_hash.as_mut() {
                    h.truncate(16);
                }
                if let Some(h) = n.metadata.file_blake3_hash.as_mut() {
                    h.truncate(16);
                }
                for m in n.metadata.methods.iter_mut() {
                    m.calls.truncate(8);
                    if let Some(d) = m.docstring.as_mut() {
                        trunc(d, 160);
                    }
                }
            }
        }

        if !compact {
            let graph = AetherGraph {
                project_name: g.project_name.clone(),
                project_path: g.project_path.clone(),
                generated_at: g.generated_at.clone(),
                system_prompt: None,
                nodes,
                edges: g.edges.clone(),
                stats: g.stats.clone(),
                dataflow_graph: None,
            };
            return UiGraphPayload {
                graph,
                edges_compact: None,
            };
        }

        let base = g.nodes.len() as u32;
        let mut id_index: HashMap<&str, u32> = HashMap::with_capacity(g.nodes.len());
        for (i, n) in g.nodes.iter().enumerate() {
            id_index.insert(n.id.as_str(), i as u32);
        }
        let mut extra_ids: Vec<String> = Vec::new();
        let mut extra_index: HashMap<String, u32> = HashMap::new();
        let mut rels: Vec<String> = Vec::new();
        let mut rel_map: HashMap<&str, u16> = HashMap::new();
        let mut types: Vec<String> = Vec::new();
        let mut types_seen: Vec<core_graph::edge::EdgeType> = Vec::new();

        let cap = g.edges.len();
        let mut src: Vec<u32> = Vec::with_capacity(cap);
        let mut dst: Vec<u32> = Vec::with_capacity(cap);
        let mut rel: Vec<u16> = Vec::with_capacity(cap);
        let mut typ: Vec<u16> = Vec::with_capacity(cap);
        let mut extra: HashMap<u32, CompactEdgeExtra> = HashMap::new();

        let mut resolve = |id: &str| -> u32 {
            if let Some(&i) = id_index.get(id) {
                return i;
            }
            if let Some(&i) = extra_index.get(id) {
                return i;
            }
            let i = base + extra_ids.len() as u32;
            extra_ids.push(id.to_string());
            extra_index.insert(id.to_string(), i);
            i
        };

        for (i, e) in g.edges.iter().enumerate() {
            src.push(resolve(&e.source));
            dst.push(resolve(&e.target));

            let ri = match rel_map.get(e.relation.as_str()) {
                Some(&r) => r,
                None => {
                    let r = rels.len() as u16;
                    rels.push(e.relation.clone());
                    rel_map.insert(e.relation.as_str(), r);
                    r
                }
            };
            rel.push(ri);

            let ti = match types_seen.iter().position(|t| *t == e.edge_type) {
                Some(p) => p as u16,
                None => {
                    types_seen.push(e.edge_type.clone());
                    types.push(format!("{:?}", e.edge_type));
                    (types.len() - 1) as u16
                }
            };
            typ.push(ti);

            let weight_set = (e.weight - 1.0).abs() > f32::EPSILON;
            let has_extra = e.cve_id.is_some()
                || e.severity.is_some()
                || e.transmitted_data.is_some()
                || e.transmitted_type.is_some()
                || e.violation_details.is_some()
                || e.label.is_some()
                || weight_set;
            if has_extra {
                extra.insert(
                    i as u32,
                    CompactEdgeExtra {
                        cve_id: e.cve_id.clone(),
                        severity: e.severity.clone(),
                        transmitted_data: e.transmitted_data.clone(),
                        transmitted_type: e.transmitted_type.clone(),
                        violation_details: e.violation_details.clone(),
                        label: e.label.clone(),
                        weight: if weight_set { Some(e.weight) } else { None },
                    },
                );
            }
        }

        let graph = AetherGraph {
            project_name: g.project_name.clone(),
            project_path: g.project_path.clone(),
            generated_at: g.generated_at.clone(),
            system_prompt: None,
            nodes,
            edges: Vec::new(),
            stats: g.stats.clone(),
            dataflow_graph: None,
        };

        UiGraphPayload {
            graph,
            edges_compact: Some(CompactEdges {
                ids: extra_ids,
                rels,
                types,
                src,
                dst,
                rel,
                typ,
                extra,
            }),
        }
    }

    /// `#[serde(serialize_with)]` : graphe allégé pour l'UI (et arêtes compactées si volumineux).
    pub fn ser_graph<S: Serializer>(g: &AetherGraph, s: S) -> Result<S::Ok, S::Error> {
        build_payload(g).serialize(s)
    }

    pub fn ser_graph_opt<S: Serializer>(g: &Option<AetherGraph>, s: S) -> Result<S::Ok, S::Error> {
        match g {
            Some(g) => ser_graph(g, s),
            None => s.serialize_none(),
        }
    }

    pub fn to_json_bytes(g: &AetherGraph) -> Vec<u8> {
        serde_json::to_vec(&build_payload(g)).unwrap_or_default()
    }
}

pub fn settings_file_path(project_root: &Path) -> PathBuf {
    project_root.join(".aether").join("settings.json")
}

pub fn load_project_settings(project_root: &Path) -> Option<SettingsPayload> {
    let p = settings_file_path(project_root);
    if p.exists() {
        if let Ok(content) = std::fs::read_to_string(&p) {
            if let Ok(settings) = serde_json::from_str::<SettingsPayload>(&content) {
                return Some(settings);
            }
        }
    }
    None
}

pub fn save_project_settings(project_root: &Path, payload: &SettingsPayload) {
    let aether_dir = project_root.join(".aether");
    let _ = std::fs::create_dir_all(&aether_dir);
    let p = aether_dir.join("settings.json");
    if let Ok(json) = serde_json::to_string_pretty(payload) {
        let _ = std::fs::write(&p, json);
    }
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
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "ui_payload::ser_graph_opt")]
    pub graph: Option<AetherGraph>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SaveFileRequest {
    pub file_path: String,
    pub content: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SaveFileResponse {
    pub status: String,
    pub file_path: String,
    pub bytes_written: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FileContentQuery {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub raw: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileTreeItem {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub extension: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectFilesResponse {
    pub status: String,
    pub files: Vec<FileTreeItem>,
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
    #[serde(serialize_with = "ui_payload::ser_graph")]
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
    #[serde(default)]
    pub forbidden_functions: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_extensions: Option<Vec<String>>,
    #[serde(default)]
    pub forbidden_extensions: Option<Vec<String>>,
    /// 0 = supprimer la limite de fichiers par dossier
    #[serde(default)]
    pub max_files_per_folder: Option<usize>,
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
    #[serde(serialize_with = "ui_payload::ser_graph")]
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
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub initial_readme: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateTaskApiRequest {
    pub task_id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub target_symbol: Option<String>,
    #[serde(default)]
    pub target_file: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub progress: Option<u8>,
    #[serde(default)]
    pub progress_note: Option<String>,
    #[serde(default)]
    pub full_readme: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

pub const AI_AGENT_PALETTE: &[&str] = &[
    "#38bdf8", // Cyan (Sky)
    "#c084fc", // Purple
    "#34d399", // Emerald
    "#f472b6", // Pink
    "#f59e0b", // Amber
    "#a3e635", // Lime
    "#22d3ee", // Bright Cyan
    "#fb7185", // Rose
    "#818cf8", // Indigo
    "#fb923c", // Orange
    "#2dd4bf", // Teal
    "#e879f9", // Fuchsia
];

pub fn assign_agent_color(agent_id: &str, agent_name: Option<&str>, explicit_color: Option<&str>) -> String {
    if let Some(c) = explicit_color.map(str::trim).filter(|s| !s.is_empty()) {
        return c.to_string();
    }
    let key = agent_id.trim();
    let key_lower = key.to_lowercase();
    let name_lower = agent_name.unwrap_or("").trim().to_lowercase();

    // Compute a deterministic hash from the full agent_id + agent_name so multiple instances
    // (e.g. claude-1, claude-2, gemini-arch, cursor-sec) get distinct colors
    let seed = if !key.is_empty() {
        format!("{}:{}", key_lower, name_lower)
    } else {
        name_lower.clone()
    };
    if seed.is_empty() || seed == "primary-agent:" {
        return AI_AGENT_PALETTE[0].to_string();
    }
    let mut hash: u64 = 14695981039346656037;
    for b in seed.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    let idx = (hash as usize) % AI_AGENT_PALETTE.len();
    AI_AGENT_PALETTE[idx].to_string()
}

/// Durée maximale (en secondes) depuis le dernier ping d'une IA pour qu'elle soit considérée connectée (5 min).
pub const AI_AGENT_TTL_SECS: u64 = 300;

pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn is_agent_ping_fresh(timestamp: u64, now_secs: u64) -> bool {
    if timestamp == 0 {
        return false;
    }
    let ts_secs = if timestamp > 100_000_000_000 {
        timestamp / 1000
    } else {
        timestamp
    };
    now_secs.saturating_sub(ts_secs) < AI_AGENT_TTL_SECS
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AiTelemetryCache {
    #[serde(default)]
    pub telemetry: Option<AiTelemetryEvent>,
    #[serde(default)]
    pub agents: Vec<AiTelemetryEvent>,
    #[serde(default)]
    pub history: Vec<AiTelemetryEvent>,
}

pub fn ai_telemetry_cache_path(project_root: &Path) -> PathBuf {
    project_root.join(".aether").join("ai_telemetry_cache.json")
}

pub fn load_ai_telemetry_cache(project_root: &Path) -> AiTelemetryCache {
    let path = ai_telemetry_cache_path(project_root);
    let now_secs = now_unix_secs();
    if let Ok(content) = std::fs::read_to_string(&path) {
        if let Ok(mut cache) = serde_json::from_str::<AiTelemetryCache>(&content) {
            cache.agents.retain(|ag| is_agent_ping_fresh(ag.timestamp, now_secs));
            for ag in &mut cache.agents {
                let id = ag.agent_id.clone().unwrap_or_else(|| "primary-agent".to_string());
                ag.color = Some(assign_agent_color(&id, ag.agent_name.as_deref(), ag.color.as_deref()));
            }
            for ev in &mut cache.history {
                let id = ev.agent_id.clone().unwrap_or_else(|| "primary-agent".to_string());
                ev.color = Some(assign_agent_color(&id, ev.agent_name.as_deref(), ev.color.as_deref()));
            }
            if let Some(ref t) = cache.telemetry {
                if !is_agent_ping_fresh(t.timestamp, now_secs) {
                    cache.telemetry = cache.agents.first().cloned();
                }
            }
            if let Some(ref mut t) = cache.telemetry {
                let id = t.agent_id.clone().unwrap_or_else(|| "primary-agent".to_string());
                t.color = Some(assign_agent_color(&id, t.agent_name.as_deref(), t.color.as_deref()));
            }
            return cache;
        }
    }
    AiTelemetryCache::default()
}

pub fn save_ai_telemetry_cache(project_root: &Path, cache: &AiTelemetryCache) {
    let aether_dir = project_root.join(".aether");
    let _ = std::fs::create_dir_all(&aether_dir);
    let path = aether_dir.join("ai_telemetry_cache.json");
    if let Ok(json_str) = serde_json::to_string_pretty(cache) {
        let _ = std::fs::write(path, json_str);
    }
}

pub fn clear_ai_telemetry_cache(project_root: &Path) {
    let path = ai_telemetry_cache_path(project_root);
    let _ = std::fs::remove_file(path);
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
    #[serde(serialize_with = "ui_payload::ser_graph")]
    pub graph: AetherGraph,
    #[serde(serialize_with = "ui_payload::ser_graph")]
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
    #[serde(serialize_with = "ui_payload::ser_graph_opt")]
    pub graph: Option<AetherGraph>,
}

// ─────────────────────────────────────────────────────────────────────────────
// M2: OBSIDIAN VAULT & DUAL-VISION MODELS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ViewModeRequest {
    pub mode: String, // "code" | "vault" (or "notes")
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphWatchEvent {
    pub version: u64,
    pub visual_version: u64,
    pub fs_version: u64,
    pub changed_files: Vec<String>,
    pub kind: String,
}

pub struct AppState {
    pub graph: RwLock<AetherGraph>,
    pub project_root: RwLock<PathBuf>,
    pub telemetry: RwLock<Option<AiTelemetryEvent>>,
    pub active_agents: RwLock<std::collections::HashMap<String, AiTelemetryEvent>>,
    pub telemetry_history: RwLock<Vec<AiTelemetryEvent>>,
    pub chat_messages: RwLock<Vec<AiChatMessage>>,
    pub graph_version: std::sync::atomic::AtomicU64,
    pub fs_version: std::sync::atomic::AtomicU64,
    pub last_changed_files: RwLock<Vec<String>>,
    pub event_tx: tokio::sync::broadcast::Sender<GraphWatchEvent>,
    pub custom_exclusions: RwLock<Vec<String>>,
    pub active_cve_rules: RwLock<Option<Vec<String>>>,
    pub ignored_cwes: RwLock<Vec<String>>,
    pub saved_ui_settings: RwLock<Option<serde_json::Value>>,
    pub show_alerts: RwLock<Option<bool>>,
    pub show_cwe_bubbles: RwLock<Option<bool>>,
    pub show_cwe_titles: RwLock<Option<bool>>,
    pub show_folder_titles: RwLock<Option<bool>>,
    pub show_file_titles: RwLock<Option<bool>>,
    pub low_memory_mode: RwLock<Option<bool>>,
    pub active_visual_plugin: RwLock<Option<String>>,
    pub visual_plugins_version: std::sync::atomic::AtomicU64,
    /// Cache des octets JSON du graphe pour l'UI (clé : version, nb noeuds, nb arêtes).
    #[allow(clippy::type_complexity)]
    pub ui_graph_cache: RwLock<Option<(u64, usize, usize, std::sync::Arc<Vec<u8>>)>>,
    /// Cache court de `git status` (évite de relancer git toutes les 2 s sur 16k fichiers).
    #[allow(clippy::type_complexity)]
    pub git_raw_cache: std::sync::Mutex<Option<(std::time::Instant, Option<(String, Option<String>)>)>>,

    // === Obsidian Vault & Dual-Vision Vision Mode Extensions (M2) ===
    pub project_type: RwLock<DetectedProjectType>,
    pub active_view_mode: RwLock<String>,
    pub code_graph: RwLock<Option<AetherGraph>>,
    pub vault_graph: RwLock<Option<AetherGraph>>,
    pub detection_report: RwLock<Option<ProjectDetectionReport>>,
    pub file_save_lock: tokio::sync::Mutex<()>,
    pub plugin_selection: security_linter::PluginSelection,
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
        let cached = load_ai_telemetry_cache(&project_root);
        let saved_settings = load_project_settings(&project_root);
        let custom_exclusions = saved_settings.as_ref().map(|s| s.exclusions.clone()).unwrap_or_default();
        let active_cve_rules = saved_settings.as_ref().and_then(|s| s.active_cve_rules.clone());
        let ignored_cwes = saved_settings.as_ref().and_then(|s| s.ignored_cwes.clone()).unwrap_or_default();
        let saved_ui_settings = saved_settings.as_ref().and_then(|s| s.ui_settings.clone());
        let show_alerts = saved_settings.as_ref().and_then(|s| s.show_alerts);
        let show_cwe_bubbles = saved_settings.as_ref().and_then(|s| s.show_cwe_bubbles);
        let show_cwe_titles = saved_settings.as_ref().and_then(|s| s.show_cwe_titles);
        let show_folder_titles = saved_settings.as_ref().and_then(|s| s.show_folder_titles);
        let show_file_titles = saved_settings.as_ref().and_then(|s| s.show_file_titles);
        let low_memory_mode = saved_settings.as_ref().and_then(|s| s.low_memory_mode);
        let active_visual_plugin = saved_settings
            .as_ref()
            .and_then(|s| s.active_visual_plugin.clone());

        let mut initial_agents = std::collections::HashMap::new();
        for ag in cached.agents {
            let key = ag.agent_id.clone().unwrap_or_else(|| "primary-agent".to_string());
            initial_agents.insert(key, ag);
        }
        let (event_tx, _) = tokio::sync::broadcast::channel(128);
        Self {
            graph: RwLock::new(graph),
            project_root: RwLock::new(project_root),
            telemetry: RwLock::new(cached.telemetry),
            active_agents: RwLock::new(initial_agents),
            telemetry_history: RwLock::new(cached.history),
            chat_messages: RwLock::new(Vec::new()),
            graph_version: std::sync::atomic::AtomicU64::new(1),
            fs_version: std::sync::atomic::AtomicU64::new(1),
            last_changed_files: RwLock::new(Vec::new()),
            event_tx,
            custom_exclusions: RwLock::new(custom_exclusions),
            active_cve_rules: RwLock::new(active_cve_rules),
            ignored_cwes: RwLock::new(ignored_cwes),
            saved_ui_settings: RwLock::new(saved_ui_settings),
            show_alerts: RwLock::new(show_alerts),
            show_cwe_bubbles: RwLock::new(show_cwe_bubbles),
            show_cwe_titles: RwLock::new(show_cwe_titles),
            show_folder_titles: RwLock::new(show_folder_titles),
            show_file_titles: RwLock::new(show_file_titles),
            low_memory_mode: RwLock::new(low_memory_mode),
            active_visual_plugin: RwLock::new(active_visual_plugin),
            visual_plugins_version: std::sync::atomic::AtomicU64::new(1),
            ui_graph_cache: RwLock::new(None),
            git_raw_cache: std::sync::Mutex::new(None),
            project_type: RwLock::new(project_type),
            active_view_mode: RwLock::new(active_view_mode),
            code_graph: RwLock::new(code_graph),
            vault_graph: RwLock::new(vault_graph),
            detection_report: RwLock::new(detection_report),
            file_save_lock: tokio::sync::Mutex::new(()),
            plugin_selection: security_linter::PluginSelection::Default,
        }
    }

    pub fn notify_graph_change(&self, changed_files: Vec<String>, kind: &str) {
        let v = self.graph_version.load(std::sync::atomic::Ordering::SeqCst);
        let vv = self.visual_plugins_version.load(std::sync::atomic::Ordering::SeqCst);
        let fv = self.fs_version.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let _ = self.event_tx.send(GraphWatchEvent {
            version: v,
            visual_version: vv,
            fs_version: fv,
            changed_files,
            kind: kind.to_string(),
        });
    }

    pub fn with_plugin_selection(mut self, selection: security_linter::PluginSelection) -> Self {
        self.plugin_selection = selection;
        self
    }

    pub async fn record_telemetry(&self, mut event: AiTelemetryEvent) -> AiTelemetryEvent {
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if event.timestamp == 0 {
            event.timestamp = now_ts;
        }
        let agent_key = event
            .agent_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "primary-agent".to_string());
        event.agent_id = Some(agent_key.clone());

        let mut agents = self.active_agents.write().await;
        let existing_color = agents.get(&agent_key).and_then(|a| a.color.clone());
        let existing_name = agents.get(&agent_key).and_then(|a| a.agent_name.clone());
        if event.agent_name.as_deref().map(str::trim).unwrap_or("").is_empty() {
            event.agent_name = existing_name;
        }
        let resolved_color = assign_agent_color(
            &agent_key,
            event.agent_name.as_deref(),
            event.color.as_deref().or(existing_color.as_deref()),
        );
        event.color = Some(resolved_color);
        agents.retain(|_, ag| is_agent_ping_fresh(ag.timestamp, now_ts));
        agents.insert(agent_key, event.clone());

        let mut agents_vec: Vec<AiTelemetryEvent> = agents.values().cloned().collect();
        agents_vec.sort_by_key(|b| std::cmp::Reverse(b.timestamp));
        drop(agents);

        let mut history = self.telemetry_history.write().await;
        let is_dup = history.first().map(|last| {
            last.agent_id == event.agent_id
                && last.target == event.target
                && last.action == event.action
                && event.timestamp.saturating_sub(last.timestamp) <= 1
        }).unwrap_or(false);

        if !is_dup {
            history.insert(0, event.clone());
            if history.len() > 250 {
                history.truncate(250);
            }
        }
        let history_clone = history.clone();
        drop(history);

        {
            let mut t = self.telemetry.write().await;
            *t = Some(event.clone());
        }

        let proj_root = self.project_root.read().await.clone();
        save_ai_telemetry_cache(
            &proj_root,
            &AiTelemetryCache {
                telemetry: Some(event.clone()),
                agents: agents_vec,
                history: history_clone,
            },
        );
        event
    }

    pub async fn reload_telemetry_cache(&self, project_root: &Path) {
        let cached = load_ai_telemetry_cache(project_root);
        let mut agents = self.active_agents.write().await;
        agents.clear();
        for ag in cached.agents {
            let key = ag.agent_id.clone().unwrap_or_else(|| "primary-agent".to_string());
            agents.insert(key, ag);
        }
        drop(agents);
        *self.telemetry.write().await = cached.telemetry;
        *self.telemetry_history.write().await = cached.history;
    }

    pub async fn clear_telemetry(&self) {
        self.active_agents.write().await.clear();
        *self.telemetry.write().await = None;
        self.telemetry_history.write().await.clear();
        let proj_root = self.project_root.read().await.clone();
        clear_ai_telemetry_cache(&proj_root);
    }

    pub async fn get_active_view_mode(&self) -> String {
        self.active_view_mode.read().await.clone()
    }

    pub async fn get_project_type(&self) -> DetectedProjectType {
        *self.project_type.read().await
    }

    pub async fn get_active_graph(&self) -> AetherGraph {
        self.graph.read().await.clone()
    }

    /// JSON du graphe pour l'UI, calculé une seule fois par version (compact si volumineux).
    pub async fn ui_graph_json(&self) -> std::sync::Arc<Vec<u8>> {
        let ver = self.graph_version.load(std::sync::atomic::Ordering::SeqCst);
        let g = self.graph.read().await;
        let key = (ver, g.nodes.len(), g.edges.len());
        if let Some((v, n, e, bytes)) = self.ui_graph_cache.read().await.as_ref() {
            if (*v, *n, *e) == key {
                return bytes.clone();
            }
        }
        let bytes = std::sync::Arc::new(ui_payload::to_json_bytes(&g));
        *self.ui_graph_cache.write().await = Some((key.0, key.1, key.2, bytes.clone()));
        bytes
    }

    /// `git status` brut mis en cache 3 s ; ne touche jamais au graphe (zéro clone).
    pub async fn git_status_cached(&self) -> GitStatusResponse {
        let p_root = self.project_root.read().await.clone();
        let cached = {
            let guard = self.git_raw_cache.lock().ok();
            guard.and_then(|g| {
                g.as_ref()
                    .filter(|(t, _)| t.elapsed() < std::time::Duration::from_secs(3))
                    .map(|(_, raw)| raw.clone())
            })
        };
        let raw = match cached {
            Some(raw) => raw,
            None => {
                let fresh = tokio::task::spawn_blocking(move || run_git_porcelain(&p_root))
                    .await
                    .ok()
                    .flatten();
                if let Ok(mut guard) = self.git_raw_cache.lock() {
                    *guard = Some((std::time::Instant::now(), fresh.clone()));
                }
                fresh
            }
        };
        match raw {
            Some((stdout, branch)) => {
                let g = self.graph.read().await;
                parse_git_status_porcelain(&stdout, branch, true, &g)
            }
            None => empty_git_status(),
        }
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
            "vault" | "notes" | "vault-notes" => "vault-notes",
            "code" => "code",
            "ide" | "editor" => "ide",
            other => {
                return Err(ViewModeError::InvalidMode(format!(
                    "Mode de vue inconnu '{}'. Modes acceptés: 'code', 'vault-notes', 'ide'.",
                    other
                )));
            }
        };

        let target_graph = match norm_mode {
            "vault-notes" => {
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
            "code" | "ide" => {
                let cached = self.code_graph.read().await.clone();
                if let Some(g) = cached {
                    g
                } else {
                    let ptype = *self.project_type.read().await;
                    if ptype.is_code() || ptype.is_mixed() {
                        let root = self.project_root.read().await.clone();
                        let excl = self.custom_exclusions.read().await.clone();
                        let sel = self.plugin_selection.clone();
                        let scanned = tokio::task::spawn_blocking(move || {
                            let scanner =
                                ast_scanner::ProjectScanner::default().with_plugin_selection(sel);
                            scanner.scan_project_with_exclusions(&root, &excl)
                        })
                        .await
                        .map_err(|e| ViewModeError::GraphNotAvailable(format!("Erreur join scan code: {}", e)))?;

                        *self.code_graph.write().await = Some(scanned.clone());
                        scanned
                    } else if norm_mode == "ide" {
                        self.graph.read().await.clone()
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
        *self.ui_graph_cache.write().await = None;
        self.graph_version.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.notify_graph_change(Vec::new(), "switch_view");

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let (action_title, details_msg) = if norm_mode == "vault-notes" {
            (
                "Bascule Vision Vault",
                format!("Vue Notes & Relations Obsidian activée ({} nœuds)", target_graph.nodes.len()),
            )
        } else if norm_mode == "ide" {
            (
                "Bascule Mode IDE",
                format!("Vue Éditeur IDE & Arborescence activée ({} symboles)", target_graph.nodes.len()),
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

    pub async fn save_file(&self, file_path: &str, content: &str) -> Result<SaveFileResponse, SecurityError> {
        let _lock = self.file_save_lock.lock().await;
        let clean_path_str = file_path.trim().to_string();
        let clean_rel = PathGuard::validate_client_relative_path(&clean_path_str)?;

        if SecretGuard::is_secret_path(&clean_rel) {
            return Err(SecurityError::SensitiveFileProhibited(clean_path_str));
        }
        PathGuard::validate_not_sensitive(&clean_rel)?;

        let p_root = self.project_root.read().await.clone();
        let guard = PathGuard::new(&p_root)?;
        let resolved_target = guard.resolve_write_target(&clean_rel)?;

        if let Some(parent) = resolved_target.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| SecurityError::IoError {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
        }

        // Atomic write: write to sibling temporary file in the same directory, then atomic rename
        let seq = ATOMIC_WRITE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_filename = format!(
            ".{}.tmp.{}_{}_{}",
            resolved_target
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "atomic_write".to_string()),
            pid,
            seq,
            nanos
        );
        let temp_target = resolved_target.parent().unwrap_or(Path::new("")).join(&temp_filename);

        fs::write(&temp_target, content.as_bytes()).map_err(|e| SecurityError::IoError {
            path: temp_target.clone(),
            source: e,
        })?;

        // Atomic replace (MoveFileExW / POSIX rename)
        let mut rename_res = fs::rename(&temp_target, &resolved_target);
        if rename_res.is_err() {
            // Transient retry for Windows file handle contention
            for attempt in 1..=20 {
                tokio::time::sleep(tokio::time::Duration::from_millis(attempt * 2)).await;
                rename_res = fs::rename(&temp_target, &resolved_target);
                if rename_res.is_ok() {
                    break;
                }
            }
        }

        if let Err(_e) = rename_res {
            let _ = fs::remove_file(&temp_target);
            // Fallback to direct write if rename fails
            let mut write_res = fs::write(&resolved_target, content.as_bytes());
            if write_res.is_err() {
                for attempt in 1..=10 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(attempt * 5)).await;
                    write_res = fs::write(&resolved_target, content.as_bytes());
                    if write_res.is_ok() {
                        break;
                    }
                }
            }
            write_res.map_err(|e| SecurityError::IoError {
                path: resolved_target.clone(),
                source: e,
            })?;
        }

        Ok(SaveFileResponse {
            status: "ok".to_string(),
            file_path: clean_path_str,
            bytes_written: content.len(),
        })
    }

    pub async fn list_files(&self) -> Vec<FileTreeItem> {
        let p_root = self.project_root.read().await.clone();
        tokio::task::spawn_blocking(move || {
            list_project_files(&p_root)
        })
        .await
        .unwrap_or_default()
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

/// Traverses `project_root` recursively using `walkdir::WalkDir`, excluding hidden/ignored
/// directories (.git, node_modules, target, dist, .aether, .gemini) and secret/sensitive files.
pub fn list_project_files(project_root: &Path) -> Vec<FileTreeItem> {
    let mut items = Vec::new();

    if !project_root.exists() || !project_root.is_dir() {
        return items;
    }

    let walker = WalkDir::new(project_root)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            if name == ".git"
                || name == "node_modules"
                || name == "target"
                || name == "dist"
                || name == ".aether"
                || name == ".gemini"
                || name.contains("WebView2")
                || (name.starts_with('.') && name.contains(".tmp."))
            {
                return false;
            }
            if let Ok(rel) = entry.path().strip_prefix(project_root) {
                if SecretGuard::is_secret_path(rel) || PathGuard::is_sensitive_path(rel) {
                    return false;
                }
            }
            true
        });

    for entry_res in walker {
        let entry = match entry_res {
            Ok(e) => e,
            Err(_) => continue,
        };

        if entry.depth() == 0 {
            continue;
        }

        let rel_path = match entry.path().strip_prefix(project_root) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if SecretGuard::is_secret_path(rel_path) || PathGuard::is_sensitive_path(rel_path) {
            continue;
        }

        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = entry.file_type().is_dir();
        let size = if is_dir {
            0
        } else {
            entry.metadata().map(|m| m.len()).unwrap_or(0)
        };
        let extension = if is_dir {
            String::new()
        } else {
            entry
                .path()
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase()
        };

        items.push(FileTreeItem {
            name,
            path: rel_str,
            is_dir,
            size,
            extension,
        });
    }

    items.sort_by(|a, b| a.path.cmp(&b.path));
    items
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

    candidates.sort_by_key(|a| a.name.to_lowercase());
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

    let structure_update = security_linter::contract::ContractStructureUpdate {
        forbidden_functions: req.forbidden_functions.clone(),
        allowed_extensions: req.allowed_extensions.clone(),
        forbidden_extensions: req.forbidden_extensions.clone(),
        max_files_per_folder: req.max_files_per_folder,
    };
    let updated_content = ReadmeContract::upsert_contract_content_with_structure(
        existing_content.as_deref(),
        &target_folder,
        req.max_lines_per_file,
        file_override_arg,
        req.allowed_imports.clone(),
        req.forbidden_imports.clone(),
        &structure_update,
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
        ("client", "---\nid: client\nlayer: ui\nmax_lines_per_file: 300\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"server::domain::*\", \"data-nodes::*\"]\n---\n# 💻 Couche Client (Interface & Présentation)\n\n> Rendu graphique, formulaires («Form») et gestion d'état local.\n\n- WHEN user interacts with view THE SYSTEM SHALL update reactive local state.\n".to_string()),
        ("client/ui", "---\nid: client-ui\nlayer: ui\nmax_lines_per_file: 250\nallowed_imports: [\"contracts::*\", \"client/state::*\"]\nforbidden_imports: [\"server::*\"]\n---\n# 🎨 Composants UI & Formulaires\n\nWHEN user submits form THE SYSTEM SHALL trigger client validation.\n".to_string()),
        ("client/state", "---\nid: client-state\nlayer: ui\nmax_lines_per_file: 200\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"server::domain::*\"]\n---\n# 🧠 Gestion d'État Client\n\nStockage réactif local et synchronisation des sessions.\n".to_string()),
        ("server", "---\nid: server\nlayer: domain\nmax_lines_per_file: 300\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"client::*\"]\nsecurity_rules:\n  no_raw_sql: true\n  no_env_access: true\n---\n# ⚡ Cœur Métier & API Serveur\n\n> Couche dissociable pouvant tourner en local ou sur serveur dédié.\n".to_string()),
        ("server/domain", "---\nid: server-domain\nlayer: domain\nmax_lines_per_file: 200\nallowed_imports: []\nforbidden_imports: [\"server/api::*\", \"client::*\", \"data-nodes::*\"]\nsecurity_rules:\n  deterministic_only: true\n---\n# 🏛️ Logique Métier Pure (Domain)\n\n100% pur, zéro dépendance I/O externe. Règles fondamentales immuables.\n\n- WHEN domain rule is evaluated THE SYSTEM SHALL execute deterministically without I/O.\n".to_string()),
        ("server/application", "---\nid: server-app\nlayer: action\nmax_lines_per_file: 250\nallowed_imports: [\"server/domain::*\", \"contracts::*\"]\nforbidden_imports: [\"client::*\"]\n---\n# ⚙️ Orchestration & Cas d'Usage\n\nServices applicatifs coordonnant le domaine et les adaptateurs.\n".to_string()),
        ("server/api", "---\nid: server-api\nlayer: action\nmax_lines_per_file: 250\nallowed_imports: [\"server/application::*\", \"contracts::*\"]\nforbidden_imports: [\"server/domain::*\"]\n---\n# 🌐 Entrées API & Contrôleurs RPC/WebSocket\n\nWHEN network packet received THE SYSTEM SHALL route through contracts schema.\n".to_string()),
        ("data-nodes", format!("---\nid: data-nodes\nlayer: database\nmax_lines_per_file: 300\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"client::*\"]\n---\n# 🗄️ Services & Nœuds de Données Dissociables\n\n> **Découplage :** {}\n", stack_db_note)),
        ("data-nodes/db-primary", "---\nid: db-primary\nlayer: database\nmax_lines_per_file: 250\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"client::*\"]\n---\n# 💾 Adaptateur Base de Données Primaire\n\nMigrations, modèles relationnels et persistance.\n".to_string()),
        ("data-nodes/cache-worker", "---\nid: cache-worker\nlayer: utility\nmax_lines_per_file: 200\nallowed_imports: [\"contracts::*\"]\nforbidden_imports: [\"client::*\"]\n---\n# ⚡ Cache & Tâches en Arrière-Plan\n\nFiles d'attente (Redis/MQ) et workers asynchrones isolables.\n".to_string()),
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

#[derive(Clone, Debug, Serialize)]
pub struct FsDirEntry {
    pub name: String,
    pub path: String,
    pub is_project: bool,
    pub stack_hint: Option<String>,
    pub is_obsidian: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct FsListResponse {
    pub status: String,
    pub current_path: String,
    pub parent_path: Option<String>,
    pub drives: Vec<String>,
    pub entries: Vec<FsDirEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

fn detect_folder_stack_hint(dir: &Path) -> (bool, Option<String>, bool) {
    let is_obsidian = dir.join(".obsidian").is_dir();
    if dir.join("Cargo.toml").is_file() {
        return (true, Some("Rust".to_string()), is_obsidian);
    }
    if dir.join("package.json").is_file() {
        return (true, Some("Node / TS".to_string()), is_obsidian);
    }
    if dir.join("pyproject.toml").is_file() || dir.join("requirements.txt").is_file() {
        return (true, Some("Python".to_string()), is_obsidian);
    }
    if dir.join("composer.json").is_file() {
        return (true, Some("PHP".to_string()), is_obsidian);
    }
    if dir.join("go.mod").is_file() {
        return (true, Some("Go".to_string()), is_obsidian);
    }
    if is_obsidian {
        return (true, Some("Obsidian Vault".to_string()), true);
    }
    if dir.join(".git").exists() {
        return (true, Some("Git".to_string()), false);
    }
    (false, None, false)
}

pub fn list_directory_entries(requested: Option<&str>, fallback_root: &Path) -> FsListResponse {
    let mut drives: Vec<String> = Vec::new();
    #[cfg(windows)]
    {
        for b in b'A'..=b'Z' {
            let root = format!("{}:\\", b as char);
            if Path::new(&root).exists() {
                drives.push(root);
            }
        }
    }
    #[cfg(not(windows))]
    {
        drives.push("/".to_string());
    }

    let target: PathBuf = match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => {
            let clean = raw.trim_matches('"').trim_matches('\'');
            let stripped = clean.strip_prefix(r"\\?\").unwrap_or(clean);
            let p = PathBuf::from(stripped);
            if p.is_file() {
                p.parent().map(Path::to_path_buf).unwrap_or(p)
            } else {
                p
            }
        }
        None => fallback_root
            .parent()
            .filter(|p| p.is_dir())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| fallback_root.to_path_buf()),
    };

    if !target.is_dir() {
        return FsListResponse {
            status: "error".to_string(),
            current_path: clean_path_string(&target),
            parent_path: target.parent().map(clean_path_string),
            drives,
            entries: Vec::new(),
            message: Some(format!("Dossier introuvable : {}", clean_path_string(&target))),
        };
    }

    let canonical = fs::canonicalize(&target).unwrap_or(target);
    let current_path = clean_path_string(&canonical);
    let parent_path = canonical.parent().map(clean_path_string);

    let mut entries: Vec<FsDirEntry> = Vec::new();
    const SKIP: &[&str] = &[
        "node_modules",
        "target",
        "dist",
        "build",
        "__pycache__",
        ".venv",
        "venv",
        "vendor",
        "$recycle.bin",
        "system volume information",
    ];

    if let Ok(rd) = fs::read_dir(&canonical) {
        for entry in rd.flatten() {
            if let Ok(ft) = entry.file_type() {
                if !ft.is_dir() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                let lower = name.to_lowercase();
                if name.starts_with('.') || SKIP.contains(&lower.as_str()) {
                    continue;
                }
                let p = entry.path();
                let (is_project, stack_hint, is_obsidian) = detect_folder_stack_hint(&p);
                entries.push(FsDirEntry {
                    name,
                    path: clean_path_string(&p),
                    is_project,
                    stack_hint,
                    is_obsidian,
                });
            }
        }
    }

    entries.sort_by(|a, b| {
        b.is_project
            .cmp(&a.is_project)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    FsListResponse {
        status: "ok".to_string(),
        current_path,
        parent_path,
        drives,
        entries,
        message: None,
    }
}

pub fn pick_folder_dialog_in(title: &str, initial_dir: Option<&Path>) -> Option<PathBuf> {
    // 1. Essai avec rfd dans un thread OS neuf (COM STA garanti propre sur Windows,
    //    sans pollution MTA du pool tokio, et sans réouvrir un second dialogue si l'utilisateur annule).
    let title_owned = title.to_string();
    let dir_owned = initial_dir.filter(|p| p.is_dir()).map(Path::to_path_buf);
    let rfd_res = std::thread::spawn(move || {
        let mut dlg = rfd::FileDialog::new().set_title(&title_owned);
        if let Some(ref d) = dir_owned {
            dlg = dlg.set_directory(d);
        }
        dlg.pick_folder()
    })
    .join();

    if let Ok(folder_opt) = rfd_res {
        return folder_opt;
    }

    // 2. Fallback Windows uniquement si rfd a paniqué/échoué (avec -STA + owner TopMost au premier plan)
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let safe_title = title.replace('\'', "''");
        let init_snippet = initial_dir
            .filter(|p| p.is_dir())
            .map(|p| {
                let s = clean_path_string(p).replace('\'', "''");
                format!("$f.SelectedPath = '{}'; ", s)
            })
            .unwrap_or_default();
        let ps_cmd = format!(
            r#"Add-Type -AssemblyName System.Windows.Forms; $owner = New-Object System.Windows.Forms.Form; $owner.TopMost = $true; $f = New-Object System.Windows.Forms.FolderBrowserDialog; $f.Description = '{}'; {}$f.ShowNewFolderButton = $true; if ($f.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {{ Write-Output $f.SelectedPath }}; $owner.Dispose()"#,
            safe_title, init_snippet
        );
        let mut cmd = std::process::Command::new("powershell");
        cmd.args(["-NoProfile", "-STA", "-Command", &ps_cmd]);
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
pub fn empty_git_status() -> GitStatusResponse {
    GitStatusResponse {
        is_git_repo: false,
        branch: None,
        clean: true,
        files: Vec::new(),
        modified_count: 0,
        untracked_count: 0,
        staged_count: 0,
        deleted_count: 0,
        security_alert_count: 0,
    }
}

/// Exécute `git status --porcelain` + branche courante. Ne dépend pas du graphe.
pub fn run_git_porcelain(project_root: &Path) -> Option<(String, Option<String>)> {
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
        _ => return None,
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

    let branch = branch_cmd.output().ok().and_then(|out| {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        } else {
            None
        }
    });

    Some((String::from_utf8_lossy(&output.stdout).to_string(), branch))
}

#[allow(dead_code)]
pub fn inspect_git_status(project_root: &Path, graph: &AetherGraph) -> GitStatusResponse {
    match run_git_porcelain(project_root) {
        Some((stdout, branch)) => parse_git_status_porcelain(&stdout, branch, true, graph),
        None => empty_git_status(),
    }
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

    // Index chemin -> noeuds construit UNE fois (avant : O(fichiers x noeuds) avec une allocation
    // de chaine par noeud et par fichier => gel total sur les gros projets).
    let mut nodes_by_path: std::collections::HashMap<String, Vec<&core_graph::bubble::SymbolBubble>> =
        std::collections::HashMap::new();
    for node in &graph.nodes {
        let key = node.file_path.trim_start_matches("./").replace('\\', "/");
        nodes_by_path.entry(key).or_default().push(node);
    }
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

        for node in nodes_by_path.get(file_path.as_str()).map(|v| v.as_slice()).unwrap_or(&[]) {
            {
                if node.has_security_violation {
                    let only_lines = !node.metadata.cve_anomalies.is_empty()
                        && node.metadata.cve_anomalies.iter().all(|a| {
                            a.rule_id == "RULE_MAX_LINES"
                                || a.cve_id.contains("ARCH-BUDGET-EXCEEDED")
                                || a.cve_id.contains("CONTRACT / ARCH-BUDGET")
                                || a.cve_id == "CONTRACT_BUDGET"
                                || (a.severity == "WARNING"
                                    && (a.rule_id.contains("LINE") || a.cve_id.contains("BUDGET")))
                        });
                    if !only_lines {
                        has_sec = true;
                    }
                }
                cwe_count += node
                    .metadata
                    .cve_anomalies
                    .iter()
                    .filter(|a| {
                        a.rule_id != "RULE_MAX_LINES"
                            && !a.cve_id.contains("ARCH-BUDGET-EXCEEDED")
                            && !a.cve_id.contains("CONTRACT / ARCH-BUDGET")
                            && a.cve_id != "CONTRACT_BUDGET"
                            && !(a.severity == "WARNING"
                                && (a.rule_id.contains("LINE") || a.cve_id.contains("BUDGET")))
                    })
                    .count();
                for anomaly in &node.metadata.cve_anomalies {
                    let sev = anomaly.severity.to_uppercase();
                    if sev == "CRITICAL" {
                        max_severity = Some("CRITICAL".to_string());
                    } else if sev == "HIGH" && max_severity.as_deref() != Some("CRITICAL") {
                        max_severity = Some("HIGH".to_string());
                    } else if max_severity.is_none()
                        || ((sev == "MEDIUM" || sev == "WARNING")
                            && (max_severity.as_deref() == Some("LOW")
                                || max_severity.as_deref() == Some("INFO")))
                    {
                        max_severity = Some(sev);
                    }
                }
                for v in &node.metadata.violations {
                    // Violations de contrat bloquantes (imports / fonctions / extensions interdits, BLAKE3 altéré)
                    if v.contains("RULE_FORBIDDEN_") || v.contains("BLAKE3_TAMPERED") {
                        ears_violation = true;
                        has_sec = true;
                        continue;
                    }
                    if v.contains("RULE_MAX_LINES")
                        || v.contains("RULE_MAX_FILES")
                        || v.contains("ARCH-BUDGET-EXCEEDED")
                        || v.contains("CONTRACT")
                    {
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
            "vault-notes".to_string(),
            None,
            Some(dummy_vault),
            None,
        );

        assert_eq!(state.get_project_type().await, DetectedProjectType::PureObsidianVault);
        assert_eq!(state.get_active_view_mode().await, "vault-notes");
        assert!(state.get_supported_views().await.contains(&"vault-notes".to_string()));
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
        let swapped = state.switch_view_mode("vault-notes").await.expect("Switch to vault should succeed");
        assert_eq!(swapped.project_name, "VaultGraph");
        assert_eq!(state.get_active_view_mode().await, "vault-notes");
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
        assert_eq!(state.get_active_view_mode().await, "vault-notes");
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
        let err = state.switch_view_mode("vault-notes").await.expect_err("Should fail");
        assert!(matches!(err, ViewModeError::GraphNotAvailable(_)));

        // "ide" and "editor" alias are supported modes and return the code graph
        let ide_res = state.switch_view_mode("ide").await.expect("Switching to 'ide' should succeed");
        assert_eq!(ide_res.project_name, "CodeGraph");
        assert_eq!(state.get_active_view_mode().await, "ide");

        let ed_res = state.switch_view_mode("editor").await.expect("Switching to 'editor' alias should succeed");
        assert_eq!(ed_res.project_name, "CodeGraph");
        assert_eq!(state.get_active_view_mode().await, "ide");

        // Invalid mode
        let err_inv = state.switch_view_mode("galaxy").await.expect_err("Should fail");
        assert!(matches!(err_inv, ViewModeError::InvalidMode(_)));
        let err_unknown = state.switch_view_mode("unknown").await.expect_err("Should fail");
        assert!(matches!(err_unknown, ViewModeError::InvalidMode(_)));
    }

    #[tokio::test]
    async fn test_app_state_save_file_confinement_and_persistence() {
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let project_root = temp_dir.path().to_path_buf();

        let dummy_graph = AetherGraph::new("TestProject");
        let state = AppState::new(
            dummy_graph.clone(),
            project_root.clone(),
            DetectedProjectType::PureCode,
            "ide".to_string(),
            Some(dummy_graph),
            None,
            None,
        );

        // 1. Valid write to source file
        let write_res = state
            .save_file("src/nested/service.rs", "fn run() -> bool { true }")
            .await
            .expect("Valid file write should succeed");
        assert_eq!(write_res.status, "ok");
        assert_eq!(write_res.file_path, "src/nested/service.rs");
        assert_eq!(write_res.bytes_written, 25);

        // Verify content on disk
        let written_disk = std::fs::read_to_string(project_root.join("src/nested/service.rs"))
            .expect("File must exist on disk");
        assert_eq!(written_disk, "fn run() -> bool { true }");

        // 2. Traversal attempt rejected
        let trav_err = state
            .save_file("../../outside.txt", "evil")
            .await
            .expect_err("Traversal must be rejected");
        assert!(matches!(trav_err, SecurityError::PathTraversal(_)));

        // 3. Absolute path rejected
        #[cfg(windows)]
        let abs_path = r"C:\Windows\System32\evil.txt";
        #[cfg(not(windows))]
        let abs_path = "/etc/passwd";
        let abs_err = state
            .save_file(abs_path, "evil")
            .await
            .expect_err("Absolute path must be rejected");
        assert!(matches!(
            abs_err,
            SecurityError::AbsolutePathsProhibited(_) | SecurityError::DriveLetterProhibited(_)
        ));

        // 4. Secret path rejected
        let sec_err = state
            .save_file(".env", "SECRET=123")
            .await
            .expect_err("Secret file write must be rejected");
        assert!(matches!(
            sec_err,
            SecurityError::SensitiveFileProhibited(_)
        ));

        let sec_err2 = state
            .save_file(".git/config", "evil")
            .await
            .expect_err("Git config write must be rejected");
        assert!(matches!(
            sec_err2,
            SecurityError::SensitiveFileProhibited(_)
        ));
    }

    #[tokio::test]
    async fn test_list_project_files_exclusions() {
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let root = temp_dir.path();

        // Create allowed files and directories
        std::fs::create_dir_all(root.join("src/sub")).unwrap();
        std::fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();
        std::fs::write(root.join("src/sub/mod.rs"), "pub mod helper;").unwrap();
        std::fs::write(root.join("README.md"), "# Hello").unwrap();

        // Create ignored directories
        std::fs::create_dir_all(root.join(".git/objects")).unwrap();
        std::fs::write(root.join(".git/config"), "secret").unwrap();

        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::write(root.join("node_modules/pkg/index.js"), "module.exports = {}").unwrap();

        std::fs::create_dir_all(root.join("target/debug")).unwrap();
        std::fs::write(root.join("target/debug/app.exe"), "bin").unwrap();

        std::fs::create_dir_all(root.join("dist/assets")).unwrap();
        std::fs::write(root.join("dist/assets/bundle.js"), "bundle").unwrap();

        std::fs::create_dir_all(root.join(".aether")).unwrap();
        std::fs::write(root.join(".aether/state.json"), "{}").unwrap();

        std::fs::create_dir_all(root.join(".gemini")).unwrap();
        std::fs::write(root.join(".gemini/cache.bin"), "cache").unwrap();

        // Create sensitive files
        std::fs::write(root.join(".env"), "API_KEY=xyz").unwrap();
        std::fs::write(root.join(".env.local"), "SECRET=xyz").unwrap();
        std::fs::write(root.join("id_rsa"), "private key").unwrap();
        std::fs::write(root.join("server.key"), "tls key").unwrap();

        // List files
        let files = list_project_files(root);

        let paths: Vec<String> = files.iter().map(|f| f.path.clone()).collect();

        // Assert allowed files are present
        assert!(paths.contains(&"README.md".to_string()), "README.md should be included");
        assert!(paths.contains(&"src".to_string()), "src dir should be included");
        assert!(paths.contains(&"src/main.rs".to_string()), "src/main.rs should be included");
        assert!(paths.contains(&"src/sub".to_string()), "src/sub dir should be included");
        assert!(paths.contains(&"src/sub/mod.rs".to_string()), "src/sub/mod.rs should be included");

        // Assert ignored directories are completely excluded
        for p in &paths {
            assert!(!p.starts_with(".git"), "Should not contain .git files: {}", p);
            assert!(!p.starts_with("node_modules"), "Should not contain node_modules files: {}", p);
            assert!(!p.starts_with("target"), "Should not contain target files: {}", p);
            assert!(!p.starts_with("dist"), "Should not contain dist files: {}", p);
            assert!(!p.starts_with(".aether"), "Should not contain .aether files: {}", p);
            assert!(!p.starts_with(".gemini"), "Should not contain .gemini files: {}", p);
            assert!(!p.contains(".env"), "Should not contain .env: {}", p);
            assert!(!p.contains("id_rsa"), "Should not contain id_rsa: {}", p);
            assert!(!p.ends_with(".key"), "Should not contain .key: {}", p);
        }

        // Check attributes on a file
        let main_rs = files.iter().find(|f| f.path == "src/main.rs").expect("src/main.rs must exist");
        assert_eq!(main_rs.name, "main.rs");
        assert!(!main_rs.is_dir);
        assert_eq!(main_rs.extension, "rs");
        assert!(main_rs.size > 0);

        // Check attributes on a directory
        let src_dir = files.iter().find(|f| f.path == "src").expect("src must exist");
        assert_eq!(src_dir.name, "src");
        assert!(src_dir.is_dir);
        assert_eq!(src_dir.extension, "");
        assert_eq!(src_dir.size, 0);
    }

    #[tokio::test]
    async fn test_file_content_raw_vs_masked_and_security() {
        let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");
        let project_root = temp_dir.path().to_path_buf();

        // Create a code file with an API key token
        std::fs::create_dir_all(project_root.join("src")).unwrap();
        let code_with_secret = "const API_KEY = \"sk-1234567890abcdef1234567890abcdef\";";
        std::fs::write(project_root.join("src/config.js"), code_with_secret).unwrap();

        let guard = PathGuard::new(&project_root).unwrap();
        let clean_rel = PathGuard::validate_client_relative_path("src/config.js").unwrap();
        let raw_content = guard.read_to_string(&clean_rel).unwrap();

        // Masked (default / raw=false)
        let masked = security_linter::SecretMasker::mask_text(&raw_content);
        assert!(!masked.contains("sk-1234567890abcdef1234567890abcdef"));
        assert!(masked.contains("[REDACTED]"));

        // Raw (raw=true for IDE editing)
        let is_raw = true;
        let final_content = if is_raw { raw_content.clone() } else { masked };
        assert_eq!(final_content, code_with_secret);

        // Security check on sensitive paths regardless of raw
        std::fs::write(project_root.join(".env"), "DATABASE_URL=postgres://...").unwrap();
        let env_rel = PathGuard::validate_client_relative_path(".env").unwrap();
        assert!(SecretGuard::is_secret_path(&env_rel));
        assert!(PathGuard::validate_not_sensitive(&env_rel).is_err());
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
                    let mode = if (i + j) % 2 == 0 { "code" } else { "vault-notes" };
                    let _ = s.switch_view_mode(mode).await;
                }
            }));
        }

        for h in handles {
            h.await.expect("Task failed");
        }

        // Verify final state is valid
        let final_mode = state.get_active_view_mode().await;
        assert!(final_mode == "code" || final_mode == "vault-notes");
        let final_graph = state.get_active_graph().await;
        assert!(final_graph.project_name == "CodeGraph" || final_graph.project_name == "VaultGraph");
    }
}

