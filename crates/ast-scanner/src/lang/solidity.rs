use core_graph::bubble::{SymbolBubble, SymbolKind};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

use crate::scanner::{
    compute_complexity, detect_galaxy, detect_layer, folder_from_rel_path, normalize_path,
    FileAnalysis, RawCall,
};

static_regex!(
    re_sol_import,
    r#"import\s+(?:(?:\{[^}]+\}|\*\s+as\s+[A-Za-z0-9_]+|[A-Za-z0-9_]+)\s+from\s+)?['"]([^'"]+)['"]"#
);
static_regex!(
    re_sol_contract,
    r#"(?:^|\n)\s*(?:(abstract)\s+)?(contract|interface|library)\s+([A-Za-z0-9_]+)(?:\s+is\s+([A-Za-z0-9_,\s]+))?"#
);
static_regex!(
    re_sol_func,
    r#"(?:^|\n)\s*function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)\s*(?:external|public|internal|private)?\s*(?:view|pure|payable)?(?:\s+(?:virtual|override(?:\([^)]*\))?))?"#
);
static_regex!(
    re_sol_modifier,
    r#"(?:^|\n)\s*modifier\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)"#
);
static_regex!(
    re_sol_call,
    r#"\b([A-Za-z0-9_]+)\s*\("#
);

pub(crate) fn analyze_solidity(rel_path: &str, content: &str) -> FileAnalysis {
    let mut nodes = Vec::new();
    let mut calls = Vec::new();
    let routes_declared = Vec::new();
    let routes_called = Vec::new();

    let galaxy = detect_galaxy(rel_path);
    let file_node_id = format!("file::{}", rel_path);
    let file_layer = detect_layer(rel_path, "");
    let file_name = Path::new(rel_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| rel_path.to_string());
    let folder = folder_from_rel_path(rel_path);

    let lines_count = content.lines().count();

    let mut file_bubble = SymbolBubble::new(
        file_node_id.clone(),
        file_name.clone(),
        rel_path.to_string(),
        1,
        SymbolKind::File,
        galaxy.clone(),
        file_layer.clone(),
    );
    file_bubble.folder = folder.clone();
    file_bubble.stereotype = "«Solidity»".to_string();
    file_bubble.docstring = format!("Contrat / Module Solidity {}", rel_path);
    file_bubble.lines_count = lines_count;
    file_bubble.complexity = compute_complexity(content);
    file_bubble.metadata.lines = lines_count;
    file_bubble.metadata.file_type = "solidity".to_string();
    nodes.push(file_bubble);

    let cur_dir = Path::new(rel_path)
        .parent()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();

    // 1. Imports
    for cap in re_sol_import().captures_iter(content) {
        if let Some(target_match) = cap.get(1) {
            let target_path = target_match.as_str();
            let norm_target = if !target_path.starts_with('/') && !target_path.starts_with('@') {
                if cur_dir.is_empty() {
                    target_path.to_string()
                } else {
                    normalize_path(&format!("{}/{}", cur_dir, target_path))
                }
            } else {
                target_path.to_string()
            };

            calls.push(RawCall {
                caller: file_node_id.clone(),
                callee: norm_target,
                relation: "imports".to_string(),
                order_label: format!("Import {}", target_path),
            });

            let stem = Path::new(target_path)
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            if !stem.is_empty() && stem != file_name {
                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: stem.clone(),
                    relation: "imports".to_string(),
                    order_label: format!("Import {}", stem),
                });
            }
        }
    }

    // 2. Contracts / Interfaces / Libraries
    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        if let Some(cap) = re_sol_contract().captures(line) {
            let is_abstract = cap.get(1).is_some();
            let kind_str = cap.get(2).map(|m| m.as_str()).unwrap_or("contract");
            let contract_name = cap.get(3).map(|m| m.as_str()).unwrap_or("");
            let inheritance = cap.get(4).map(|m| m.as_str()).unwrap_or("");

            if !contract_name.is_empty() {
                let c_node_id = format!("{}::{}", file_node_id, contract_name);
                let mut c_bubble = SymbolBubble::new(
                    c_node_id.clone(),
                    contract_name.to_string(),
                    rel_path.to_string(),
                    line_num,
                    SymbolKind::Contract,
                    galaxy.clone(),
                    file_layer.clone(),
                );
                c_bubble.folder = folder.clone();
                c_bubble.stereotype = if is_abstract {
                    "«AbstractContract»".to_string()
                } else {
                    match kind_str {
                        "interface" => "«Interface»".to_string(),
                        "library" => "«Library»".to_string(),
                        _ => "«Contract»".to_string(),
                    }
                };
                c_bubble.docstring = format!("{} Solidity {}", kind_str, contract_name);
                nodes.push(c_bubble);

                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: c_node_id.clone(),
                    relation: "contains".to_string(),
                    order_label: "Définit".to_string(),
                });

                if !inheritance.is_empty() {
                    for parent in inheritance.split(',') {
                        let p_name = parent.trim();
                        if !p_name.is_empty() {
                            calls.push(RawCall {
                                caller: c_node_id.clone(),
                                callee: p_name.to_string(),
                                relation: "inherits".to_string(),
                                order_label: format!("Hérite de {}", p_name),
                            });
                        }
                    }
                }
            }
        } else if let Some(cap) = re_sol_func().captures(line) {
            let func_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let params = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            if !func_name.is_empty() {
                let fn_node_id = format!("{}::fn::{}", file_node_id, func_name);
                let mut fn_bubble = SymbolBubble::new(
                    fn_node_id.clone(),
                    func_name.to_string(),
                    rel_path.to_string(),
                    line_num,
                    SymbolKind::Function,
                    galaxy.clone(),
                    file_layer.clone(),
                );
                fn_bubble.folder = folder.clone();
                fn_bubble.stereotype = "«Function»".to_string();
                fn_bubble.docstring = format!("function {}({})", func_name, params);
                nodes.push(fn_bubble);

                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: fn_node_id.clone(),
                    relation: "contains".to_string(),
                    order_label: "Fonction".to_string(),
                });
            }
        } else if let Some(cap) = re_sol_modifier().captures(line) {
            let mod_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if !mod_name.is_empty() {
                let mod_node_id = format!("{}::mod::{}", file_node_id, mod_name);
                let mut mod_bubble = SymbolBubble::new(
                    mod_node_id.clone(),
                    mod_name.to_string(),
                    rel_path.to_string(),
                    line_num,
                    SymbolKind::Function,
                    galaxy.clone(),
                    file_layer.clone(),
                );
                mod_bubble.folder = folder.clone();
                mod_bubble.stereotype = "«Modifier»".to_string();
                mod_bubble.docstring = format!("modifier {}", mod_name);
                nodes.push(mod_bubble);

                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: mod_node_id.clone(),
                    relation: "contains".to_string(),
                    order_label: "Modifier".to_string(),
                });
            }
        }
    }

    // 3. Appels de fonctions internes / inter-contrats
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }
        for cap in re_sol_call().captures_iter(line) {
            if let Some(target) = cap.get(1) {
                let t_name = target.as_str();
                let ignore = ["require", "assert", "revert", "keccak256", "abi", "type", "if", "for", "while", "return", "returns", "emit", "super", "assembly"];
                if !ignore.contains(&t_name) && t_name.len() > 2 {
                    calls.push(RawCall {
                        caller: file_node_id.clone(),
                        callee: t_name.to_string(),
                        relation: "calls".to_string(),
                        order_label: format!("Appel {}", t_name),
                    });
                }
            }
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
        ws_handlers: Vec::new(),
        ws_emits: Vec::new(),
    }
}
