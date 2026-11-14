use core_graph::graph::AetherGraph;
use obsidian_vault::types::DetectedProjectType;
use serde::Serialize;

pub const PHYSICS_WORKER_JS: &str = include_str!("../ui/src/engine/physics.worker.js");
pub const DIST_INDEX_HTML: &str = include_str!("../dist/index.html");
#[allow(dead_code)]
pub const MODERN_INDEX_HTML: &str = DIST_INDEX_HTML;

/// Dual-vision graph container serialized for offline standalone bundles.
#[derive(Debug, Clone, Serialize)]
pub struct DualGraphBundle<'a> {
    pub project_type: &'a str,
    pub supported_views: Vec<&'static str>,
    pub active_view: &'a str,
    pub code: Option<&'a AetherGraph>,
    pub vault: Option<&'a AetherGraph>,
}

fn ensure_system_prompt(graph: &AetherGraph) -> AetherGraph {
    let mut graph_clone = graph.clone();
    if graph_clone.system_prompt.is_none() {
        let p_path = graph_clone
            .project_path
            .as_deref()
            .unwrap_or(&graph_clone.project_name);
        let p_buf = std::path::PathBuf::from(p_path);
        let stack_str = ai_file_bridge::audit_writer::AuditWriter::detect_project_stack(&p_buf);
        let prompt = ai_file_bridge::audit_writer::AuditWriter::generate_optimized_system_prompt(
            &p_buf,
            &graph_clone.project_name,
            stack_str,
            3030,
        );
        graph_clone.system_prompt = Some(prompt);
    }
    graph_clone
}

/// Generates a standalone self-contained HTML bundle embedding both Code and Vault graphs
/// for dual-vision mode when generated from Mixed or single-mode projects.
#[allow(dead_code)]
pub fn generate_dual_standalone_html(
    code_graph: Option<&AetherGraph>,
    vault_graph: Option<&AetherGraph>,
    project_type: DetectedProjectType,
    active_view: &str,
) -> String {
    generate_modern_standalone_html(code_graph, vault_graph, project_type, active_view)
}

/// Generates a modern Svelte 5 + Vite standalone HTML bundle (ultra-lightweight ~145 KB)
pub fn generate_modern_standalone_html(
    code_graph: Option<&AetherGraph>,
    vault_graph: Option<&AetherGraph>,
    project_type: DetectedProjectType,
    active_view: &str,
) -> String {
    let code_prepared = code_graph.map(ensure_system_prompt);
    let vault_prepared = vault_graph.map(ensure_system_prompt);

    let norm_active = match active_view.trim().to_lowercase().as_str() {
        "vault" | "notes" => "vault",
        _ => "code",
    };

    let worker_json = serde_json::to_string(PHYSICS_WORKER_JS)
        .unwrap_or_default()
        .replace("</", "<\\/")
        .replace("<!--", "<\\!--");

    let dual_bundle = DualGraphBundle {
        project_type: project_type.as_str(),
        supported_views: project_type.supported_views(),
        active_view: norm_active,
        code: code_prepared.as_ref(),
        vault: vault_prepared.as_ref(),
    };
    let dual_json = serde_json::to_string(&dual_bundle).unwrap_or_default();
    let safe_dual_json = dual_json
        .replace("</", "<\\/")
        .replace("<!--", "<\\!--");

    let active_key = if norm_active == "vault" { "vault" } else { "code" };
    let injection = format!(
        "<div id=\"view-mode-toggle\" style=\"display:none\" aria-hidden=\"true\">\n\
         <button id=\"btn-view-mode-code\" onclick=\"switchProjectViewMode('code')\"></button>\n\
         <button id=\"btn-view-mode-vault\" onclick=\"switchProjectViewMode('vault')\"></button>\n\
         <button id=\"btn-menu-view-code\" onclick=\"switchProjectViewMode('code')\"></button>\n\
         <button id=\"btn-menu-view-vault\" onclick=\"switchProjectViewMode('vault')\"></button>\n\
         </div>\n\
         <script>\n\
         window.__AETHERSCOPE_DUAL_GRAPH__ = {};\n\
         window.__PHYSICS_WORKER_CODE__ = {};\n\
         window.__AETHERSCOPE_DATA__ = window.__AETHERSCOPE_DUAL_GRAPH__.{} || window.__AETHERSCOPE_DUAL_GRAPH__.code || window.__AETHERSCOPE_DUAL_GRAPH__.vault || {{ project_name: 'AetherScope', nodes: [], edges: [], stats: {{}} }};\n\
         window.AETHER_GRAPH_DATA = window.__AETHERSCOPE_DATA__;\n\
         window.AETHER_DUAL_GRAPH = window.__AETHERSCOPE_DUAL_GRAPH__;\n\
         async function switchProjectViewMode(mode) {{\n\
             if (window.__AETHERSCOPE_DUAL_GRAPH__ && window.__AETHERSCOPE_DUAL_GRAPH__[mode]) {{\n\
                 window.__AETHERSCOPE_DATA__ = window.__AETHERSCOPE_DUAL_GRAPH__[mode];\n\
                 window.AETHER_GRAPH_DATA = window.__AETHERSCOPE_DATA__;\n\
                 if (window.dispatchEvent) {{\n\
                     window.dispatchEvent(new CustomEvent('aether:viewmode', {{ detail: mode }}));\n\
                 }}\n\
             }}\n\
         }}\n\
         async function fetchProjectStatus() {{\n\
             return {{ project_type: window.__AETHERSCOPE_DUAL_GRAPH__?.project_type || 'Mixed' }};\n\
         }}\n\
         </script>",
        safe_dual_json, worker_json, active_key
    );

    if let Some(pos) = DIST_INDEX_HTML.rfind("<div id=\"app\"></div>") {
        let mut out = String::with_capacity(DIST_INDEX_HTML.len() + injection.len() + 16);
        out.push_str(&DIST_INDEX_HTML[..pos]);
        out.push_str(&injection);
        out.push_str("\n    ");
        out.push_str(&DIST_INDEX_HTML[pos..]);
        out
    } else if let Some(pos) = DIST_INDEX_HTML.rfind("<body") {
        let mut out = String::with_capacity(DIST_INDEX_HTML.len() + injection.len() + 16);
        out.push_str(&DIST_INDEX_HTML[..pos]);
        out.push_str(&injection);
        out.push('\n');
        out.push_str(&DIST_INDEX_HTML[pos..]);
        out
    } else {
        format!("{}\n{}", injection, DIST_INDEX_HTML)
    }
}

/// Backward compatible generator for single graph export.
#[allow(dead_code)]
pub fn generate_standalone_html(graph: &AetherGraph) -> String {
    generate_dual_standalone_html(
        Some(graph),
        None,
        DetectedProjectType::PureCode,
        "code",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_graph::bubble::{SymbolBubble, SymbolKind};

    #[test]
    fn test_generate_standalone_html() {
        let graph = AetherGraph::new("TestProject");
        let html = generate_standalone_html(&graph);

        assert!(html.contains("<!doctype html>") || html.contains("<!DOCTYPE html>"));
        assert!(html.contains("window.__AETHERSCOPE_DATA__"));
        assert!(html.contains("window.__AETHERSCOPE_DUAL_GRAPH__"));
        assert!(html.contains("window.AETHER_GRAPH_DATA"));
        assert!(html.contains("window.AETHER_DUAL_GRAPH"));
        assert!(html.contains("window.__PHYSICS_WORKER_CODE__"));
        assert!(html.contains("system_prompt"));
        assert!(html.contains("aether-canvas") || html.contains("AetherScope") || html.contains("physics_worker"));
        assert!(!html.contains("src=\"app.js\""));
        assert!(!html.contains("src=\"state_api.js\""));
        assert!(!html.contains("href=\"styles.css\""));
        assert!(html.len() > 50_000);
    }

    #[test]
    fn test_generate_modern_standalone_html() {
        let graph = AetherGraph::new("ModernProject");
        let html = generate_modern_standalone_html(
            Some(&graph),
            None,
            DetectedProjectType::PureCode,
            "code",
        );

        assert!(html.contains("window.__AETHERSCOPE_DATA__"));
        assert!(html.contains("window.__AETHERSCOPE_DUAL_GRAPH__"));
        assert!(html.contains("window.AETHER_GRAPH_DATA"));
        assert!(html.contains("aether-canvas"));
        assert_eq!(html.matches("<div id=\"view-mode-toggle\"").count(), 1);
        assert_eq!(html.matches("window.__AETHERSCOPE_DUAL_GRAPH__ =").count(), 1);
        assert!(html.len() > 50_000);
    }

    #[test]
    fn test_generate_dual_standalone_html_mixed() {
        let mut code_graph = AetherGraph::new("MixedCodeProject");
        code_graph.add_node(SymbolBubble::new(
            "crates/core/src/main.rs::run".to_string(),
            "run".to_string(),
            "crates/core/src/main.rs".to_string(),
            10,
            SymbolKind::Function,
            "server".to_string(),
            "domain".to_string(),
        ));

        let mut vault_graph = AetherGraph::new("MixedVaultNotes");
        vault_graph.add_node(SymbolBubble::new(
            "note::Architecture".to_string(),
            "Architecture".to_string(),
            "notes/Architecture.md".to_string(),
            1,
            SymbolKind::File,
            "contracts".to_string(),
            "docs".to_string(),
        ));

        let html = generate_dual_standalone_html(
            Some(&code_graph),
            Some(&vault_graph),
            DetectedProjectType::Mixed,
            "code",
        );

        assert!(html.contains("window.__AETHERSCOPE_DATA__"));
        assert!(html.contains("window.__AETHERSCOPE_DUAL_GRAPH__"));
        assert!(html.contains("window.AETHER_DUAL_GRAPH"));
        assert!(html.contains("\"project_type\":\"Mixed\""));
        assert!(html.contains("\"supported_views\":[\"code\",\"vault\"]"));
        assert!(html.contains("\"active_view\":\"code\""));
        assert!(html.contains("crates/core/src/main.rs::run"));
        assert!(html.contains("note::Architecture"));
    }

    #[test]
    fn test_generate_dual_standalone_html_vault_active() {
        let mut vault_graph = AetherGraph::new("PureVaultProject");
        vault_graph.add_node(SymbolBubble::new(
            "note::Index".to_string(),
            "Index".to_string(),
            "Index.md".to_string(),
            1,
            SymbolKind::File,
            "contracts".to_string(),
            "docs".to_string(),
        ));

        let html = generate_dual_standalone_html(
            None,
            Some(&vault_graph),
            DetectedProjectType::PureObsidianVault,
            "vault",
        );

        assert!(html.contains("window.__AETHERSCOPE_DATA__"));
        assert!(html.contains("\"project_type\":\"PureObsidianVault\""));
        assert!(html.contains("\"supported_views\":[\"vault\",\"code\"]"));
        assert!(html.contains("\"active_view\":\"vault\""));
        assert!(html.contains("note::Index"));
    }

    #[test]
    fn test_generate_dual_standalone_html_pure_code() {
        let mut code_graph = AetherGraph::new("PureCodeProject");
        code_graph.add_node(SymbolBubble::new(
            "src/lib.rs::compute".to_string(),
            "compute".to_string(),
            "src/lib.rs".to_string(),
            5,
            SymbolKind::Function,
            "server".to_string(),
            "domain".to_string(),
        ));

        let html = generate_dual_standalone_html(
            Some(&code_graph),
            None,
            DetectedProjectType::PureCode,
            "code",
        );

        assert!(html.contains("\"project_type\":\"PureCode\""));
        assert!(html.contains("\"supported_views\":[\"code\"]"));
        assert!(html.contains("\"vault\":null"));
        assert!(html.contains("src/lib.rs::compute"));
    }

    #[test]
    fn test_export_docs_index_html() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = std::fs::canonicalize(manifest_dir.join("../..")).unwrap();
        let scanner = ast_scanner::scanner::ProjectScanner::default();
        let code_graph = scanner.scan_project(&root);
        println!("Exporting docs/index.html for root: {:?}, nodes: {}", root, code_graph.nodes.len());
        assert!(code_graph.nodes.len() > 50, "Graph must contain nodes!");

        let detection_report = obsidian_vault::detect_project_type(&root).ok();
        let project_type = detection_report
            .as_ref()
            .map(|r| r.project_type)
            .unwrap_or(obsidian_vault::DetectedProjectType::PureCode);
        let active_view_mode = detection_report
            .as_ref()
            .map(|r| r.default_view.clone())
            .unwrap_or_else(|| "code".to_string());

        let vault_graph = if project_type.is_vault() || project_type.is_mixed() {
            obsidian_vault::scan_obsidian_vault(&root).ok()
        } else {
            None
        };

        let html = generate_dual_standalone_html(
            Some(&code_graph),
            vault_graph.as_ref(),
            project_type,
            &active_view_mode,
        );
        let docs_path = root.join("docs/index.html");
        let _ = std::fs::write(&docs_path, &html);
        assert!(html.contains("window.__AETHERSCOPE_DATA__"));
        assert!(html.contains("system_prompt"));
        assert!(html.contains("window.__AETHERSCOPE_DUAL_GRAPH__"));
    }
}
