use core_graph::bubble::{AstAttribute, AstMethod, SymbolBubble, SymbolKind};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use crate::scanner::{
    compute_complexity, detect_galaxy, detect_layer, detect_stereotype, folder_from_rel_path,
    line_number_at, normalize_path, safe_slice, FileAnalysis, RawCall,
};

static_regex!(re_cpp_include, r#"#include\s*([<"])([^>"]+)[>"]"#);
static_regex!(
    re_cpp_class,
    r#"(?:template\s*<[^>]*>\s*)?(?:class|struct)\s+([A-Za-z0-9_]+)(?:\s*:\s*([^{;]+))?\s*\{"#
);
static_regex!(
    re_cpp_member_method,
    r#"(?:^|\n)\s*(?:(?:virtual|static|inline|explicit)\s+)*(?:[A-Za-z0-9_:<>&*~]+\s+)+([A-Za-z0-9_]+)\s*\(([^)]*)\)"#
);
static_regex!(
    re_cpp_member_field,
    r#"(?:^|\n)\s*(?:[A-Za-z0-9_:<>&*]+\s+)+([A-Za-z0-9_]+)\s*;"#
);
static_regex!(
    re_cpp_func,
    r#"(?:^|\n)\s*(?:(?:virtual|static|inline|explicit|constexpr|friend)\s+)*(?:[A-Za-z0-9_:<>&*~]+\s+)+([A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)?)\s*\(([^)]*)\)\s*(?:const|override|noexcept)?\s*\{"#
);
static_regex!(
    re_cpp_call,
    r#"\b([A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)?)\s*\("#
);

fn is_cpp_keyword(word: &str) -> bool {
    matches!(
        word,
        "if" | "else"
            | "for"
            | "while"
            | "do"
            | "switch"
            | "case"
            | "default"
            | "return"
            | "break"
            | "continue"
            | "goto"
            | "try"
            | "catch"
            | "throw"
            | "sizeof"
            | "alignof"
            | "decltype"
            | "typeid"
            | "new"
            | "delete"
            | "static_cast"
            | "dynamic_cast"
            | "reinterpret_cast"
            | "const_cast"
            | "struct"
            | "class"
            | "union"
            | "enum"
            | "namespace"
            | "template"
            | "typename"
            | "public"
            | "private"
            | "protected"
            | "virtual"
            | "override"
            | "final"
            | "const"
            | "static"
            | "inline"
            | "constexpr"
            | "explicit"
            | "friend"
            | "auto"
            | "void"
            | "int"
            | "char"
            | "float"
            | "double"
            | "bool"
            | "short"
            | "long"
            | "unsigned"
            | "signed"
            | "true"
            | "false"
            | "nullptr"
            | "this"
    )
}

pub(crate) fn analyze_cpp(rel_path: &str, content: &str) -> FileAnalysis {
    let mut nodes = Vec::new();
    let mut calls = Vec::new();

    let galaxy = detect_galaxy(rel_path);
    let file_node_id = format!("file::{}", rel_path);
    let file_layer = detect_layer(rel_path, "");
    let file_name = Path::new(rel_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| rel_path.to_string());
    let folder = folder_from_rel_path(rel_path);

    let lines_count = content.lines().count();
    let is_header = rel_path.ends_with(".h")
        || rel_path.ends_with(".hpp")
        || rel_path.ends_with(".hh")
        || rel_path.ends_with(".hxx");

    let mut file_bubble = SymbolBubble::new(
        file_node_id.clone(),
        file_name.clone(),
        rel_path.to_string(),
        1,
        SymbolKind::File,
        galaxy.clone(),
        file_layer,
    );
    file_bubble.folder = folder.clone();
    file_bubble.stereotype = if is_header {
        "«Header»".to_string()
    } else {
        "«File»".to_string()
    };
    file_bubble.docstring = format!("Fichier source C/C++ {}", rel_path);
    file_bubble.lines_count = lines_count;
    file_bubble.complexity = compute_complexity(content);
    file_bubble.metadata.lines = lines_count;
    file_bubble.metadata.file_type = "cpp".to_string();
    nodes.push(file_bubble);

    let cur_dir = Path::new(rel_path)
        .parent()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();

    // 1. Includes
    for cap in re_cpp_include().captures_iter(content) {
        let is_quoted = cap.get(1).map(|m| m.as_str() == "\"").unwrap_or(false);
        if let Some(target_match) = cap.get(2) {
            let target_path = target_match.as_str();
            let norm_target = if is_quoted && !target_path.starts_with('/') {
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
                order_label: format!("Include {}", target_path),
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
                    order_label: format!("Include {}", stem),
                });
            }
        }
    }

    // 2. Classes & Structs
    for cap in re_cpp_class().captures_iter(content) {
        let class_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if class_name.is_empty() || is_cpp_keyword(class_name) {
            continue;
        }
        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(content, match_0.start());

        let bases_str = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let bases: Vec<String> = bases_str
            .split(',')
            .map(|s| {
                s.replace("public", "")
                    .replace("protected", "")
                    .replace("private", "")
                    .replace("virtual", "")
                    .trim()
                    .to_string()
            })
            .filter(|s| !s.is_empty())
            .collect();

        let node_id = format!("{}::{}", rel_path, class_name);
        let layer = detect_layer(rel_path, class_name);
        let stereo = detect_stereotype(class_name, true, &layer, &bases);

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        for base in &bases {
            calls.push(RawCall {
                caller: node_id.clone(),
                callee: base.clone(),
                relation: "inherits".to_string(),
                order_label: format!("Hérite de {}", base),
            });
        }

        let mut attributes = Vec::new();
        let mut methods = Vec::new();

        let class_body_slice = safe_slice(content, match_0.end(), 8000);
        let class_body = if let Some(close_idx) = class_body_slice.find("};") {
            safe_slice(class_body_slice, 0, close_idx)
        } else {
            safe_slice(class_body_slice, 0, 2000)
        };

        for m_cap in re_cpp_member_method().captures_iter(class_body) {
            let m_name = m_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if !m_name.is_empty() && !is_cpp_keyword(m_name) {
                let args = m_cap.get(2).map(|m| m.as_str().to_string());
                methods.push(AstMethod {
                    name: m_name.to_string(),
                    args,
                    returns: None,
                    is_async: None,
                    calls: Vec::new(),
                    docstring: None,
                });
            }
        }

        for f_cap in re_cpp_member_field().captures_iter(class_body) {
            let f_name = f_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if !f_name.is_empty() && !is_cpp_keyword(f_name) {
                attributes.push(AstAttribute {
                    name: f_name.to_string(),
                    r#type: None,
                });
            }
        }

        let mut class_bubble = SymbolBubble::new(
            node_id,
            class_name.to_string(),
            rel_path.to_string(),
            line_no,
            SymbolKind::ClassOrStruct,
            galaxy.clone(),
            layer,
        );
        class_bubble.folder = folder.clone();
        class_bubble.stereotype = stereo;
        class_bubble.complexity = compute_complexity(class_body);
        class_bubble.docstring = format!("Classe/Structure C++ {}", class_name);
        class_bubble.metadata.attributes = attributes;
        class_bubble.metadata.methods = methods;
        nodes.push(class_bubble);
    }

    // 3. Functions & Methods
    let mut seen_funcs = HashSet::new();

    for cap in re_cpp_func().captures_iter(content) {
        if let Some(m) = cap.get(1) {
            let full_func_name = m.as_str();
            let short_name = full_func_name.split("::").last().unwrap_or(full_func_name);
            if is_cpp_keyword(short_name) || is_cpp_keyword(full_func_name) {
                continue;
            }
            if !seen_funcs.insert(full_func_name.to_string()) {
                continue;
            }
            let match_0 = cap.get(0).unwrap();
            let line_no = line_number_at(content, match_0.start());
            let node_id = format!("{}::{}", rel_path, full_func_name);
            let layer = detect_layer(rel_path, full_func_name);
            let stereo = if full_func_name.contains("::") {
                "«Method»".to_string()
            } else {
                detect_stereotype(short_name, false, &layer, &[])
            };

            calls.push(RawCall {
                caller: file_node_id.clone(),
                callee: node_id.clone(),
                relation: "contains".to_string(),
                order_label: "Contient".to_string(),
            });

            if let Some((class_name, _)) = full_func_name.split_once("::") {
                calls.push(RawCall {
                    caller: format!("{}::{}", rel_path, class_name),
                    callee: node_id.clone(),
                    relation: "contains".to_string(),
                    order_label: "Méthode".to_string(),
                });
            }

            let body_slice = safe_slice(content, match_0.end(), 4000);
            for c_cap in re_cpp_call().captures_iter(body_slice) {
                let callee = c_cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let callee_short = callee.split("::").last().unwrap_or(callee);
                if !callee.is_empty()
                    && callee != full_func_name
                    && callee_short != short_name
                    && !is_cpp_keyword(callee_short)
                {
                    calls.push(RawCall {
                        caller: node_id.clone(),
                        callee: callee_short.to_string(),
                        relation: "calls".to_string(),
                        order_label: format!("Appel {}", callee_short),
                    });
                }
            }

            let mut fn_bubble = SymbolBubble::new(
                node_id,
                full_func_name.to_string(),
                rel_path.to_string(),
                line_no,
                SymbolKind::Function,
                galaxy.clone(),
                layer,
            );
            fn_bubble.folder = folder.clone();
            fn_bubble.stereotype = stereo;
            fn_bubble.complexity = compute_complexity(body_slice);
            fn_bubble.docstring = format!("Fonction/Méthode C++ {}", full_func_name);
            nodes.push(fn_bubble);
        }
    }

    FileAnalysis {
        rel_path: rel_path.to_string(),
        folder,
        raw_content: content.to_string(),
        nodes,
        calls,
        routes_declared: Vec::new(),
        routes_called: Vec::new(),
        ws_handlers: Vec::new(),
        ws_emits: Vec::new(),
    }
}
