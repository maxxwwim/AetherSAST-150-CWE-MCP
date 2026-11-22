use core_graph::bubble::{SymbolBubble, SymbolKind};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

use crate::scanner::{
    compute_complexity, detect_galaxy, detect_layer, folder_from_rel_path, line_number_at,
    FileAnalysis, RawCall,
};

static_regex!(
    re_luau_func,
    r#"(?:^|\n)\s*(?:local\s+)?function\s+([A-Za-z0-9_.:]+)\s*\(([^)]*)\)"#
);
static_regex!(
    re_luau_type,
    r#"(?:^|\n)\s*(?:export\s+)?type\s+([A-Za-z0-9_]+)\s*="#
);
static_regex!(
    re_luau_require,
    r#"require\s*\(\s*([^)]+)\s*\)"#
);

pub(crate) fn analyze_luau(rel_path: &str, content: &str) -> FileAnalysis {
    let mut nodes = Vec::new();
    let mut calls = Vec::new();
    let routes_declared = Vec::new();
    let routes_called = Vec::new();
    let ws_handlers = Vec::new();
    let ws_emits = Vec::new();

    let galaxy = detect_galaxy(rel_path);
    let file_node_id = format!("file::{}", rel_path);
    let file_layer = detect_layer(rel_path, "");
    let file_name = Path::new(rel_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| rel_path.to_string());
    let folder = folder_from_rel_path(rel_path);

    let mut file_bubble = SymbolBubble::new(
        file_node_id.clone(),
        file_name,
        rel_path.to_string(),
        1,
        SymbolKind::File,
        galaxy.clone(),
        file_layer,
    );
    file_bubble.folder = folder.clone();
    file_bubble.docstring = format!("Module Luau Roblox {}", rel_path);
    file_bubble.lines_count = content.lines().count();
    file_bubble.complexity = compute_complexity(content);
    file_bubble.metadata.lines = file_bubble.lines_count;
    file_bubble.metadata.file_type = "luau".to_string();
    nodes.push(file_bubble);

    for cap in re_luau_type().captures_iter(content) {
        if let Some(t_match) = cap.get(1) {
            let type_name = t_match.as_str().to_string();
            let line_num = line_number_at(content, t_match.start());
            let sym_id = format!("type::{}::{}", rel_path, type_name);
            let mut bubble = SymbolBubble::new(
                sym_id.clone(),
                type_name,
                rel_path.to_string(),
                line_num,
                SymbolKind::Contract,
                galaxy.clone(),
                detect_layer(rel_path, "type"),
            );
            bubble.folder = folder.clone();
            nodes.push(bubble);

            calls.push(RawCall {
                caller: file_node_id.clone(),
                callee: sym_id,
                relation: "defines".to_string(),
                order_label: "".to_string(),
            });
        }
    }

    for cap in re_luau_func().captures_iter(content) {
        if let Some(fn_match) = cap.get(1) {
            let fn_name = fn_match.as_str().to_string();
            let line_num = line_number_at(content, fn_match.start());
            let sym_id = format!("fn::{}::{}", rel_path, fn_name);
            let mut bubble = SymbolBubble::new(
                sym_id.clone(),
                fn_name,
                rel_path.to_string(),
                line_num,
                SymbolKind::Function,
                galaxy.clone(),
                detect_layer(rel_path, "function"),
            );
            bubble.folder = folder.clone();
            nodes.push(bubble);

            calls.push(RawCall {
                caller: file_node_id.clone(),
                callee: sym_id,
                relation: "defines".to_string(),
                order_label: "".to_string(),
            });
        }
    }

    for cap in re_luau_require().captures_iter(content) {
        if let Some(req_match) = cap.get(1) {
            let raw_req = req_match.as_str().trim().trim_matches('"').trim_matches('\'');
            calls.push(RawCall {
                caller: file_node_id.clone(),
                callee: format!("require::{}", raw_req),
                relation: "imports".to_string(),
                order_label: "".to_string(),
            });
        }
    }

    FileAnalysis {
        rel_path: rel_path.to_string(),
        folder,
        raw_content: content.to_string(),
        nodes,
        calls,
        routes_declared,
        routes_called,
        ws_handlers,
        ws_emits,
    }
}
