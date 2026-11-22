use core_graph::bubble::{AstAttribute, AstMethod, SymbolBubble, SymbolKind};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

use super::re_call_ident;
use crate::scanner::{
    compute_complexity, detect_galaxy, detect_layer, detect_stereotype, extract_leading_doc,
    folder_from_rel_path, line_number_at, safe_slice, FileAnalysis, RawCall,
};

static_regex!(
    re_py_import,
    r#"(?:^|\n)\s*(?:from\s+([a-zA-Z0-9_\.]+)\s+import\s+([a-zA-Z0-9_,\s\*]+)|import\s+([a-zA-Z0-9_,\s]+))"#
);
static_regex!(
    re_py_class,
    r#"(?:^|\n)class\s+([A-Za-z0-9_]+)(?:\(([^)]*)\))?:"#
);
static_regex!(
    re_py_field,
    r#"(?:^|\n)\s+([a-zA-Z0-9_]+)\s*:\s*([A-Za-z0-9_\[\], ]+)"#
);
static_regex!(
    re_py_func,
    r#"(?:^|\n)(?:async\s+)?def\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)"#
);
static_regex!(re_py_route_str, r#"['"](/api/[^'"]+)['"]"#);

fn extract_python_docstring(body_slice: &str) -> String {
    let trimmed = body_slice.trim_start();
    if let Some(rest) = trimmed.strip_prefix("\"\"\"") {
        if let Some(end) = rest.find("\"\"\"") {
            return rest[..end].trim().to_string();
        }
    } else if let Some(rest) = trimmed.strip_prefix("'''") {
        if let Some(end) = rest.find("'''") {
            return rest[..end].trim().to_string();
        }
    }
    String::new()
}

fn is_py_keyword(word: &str) -> bool {
    matches!(
        word,
        "if" | "elif"
            | "for"
            | "while"
            | "return"
            | "yield"
            | "print"
            | "len"
            | "range"
            | "str"
            | "int"
            | "float"
            | "list"
            | "dict"
            | "set"
            | "tuple"
            | "super"
            | "isinstance"
    )
}

pub(crate) fn analyze_python(rel_path: &str, content: &str) -> FileAnalysis {
    let mut nodes = Vec::new();
    let mut calls = Vec::new();
    let mut routes_declared = Vec::new();
    let mut routes_called = Vec::new();
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
    file_bubble.docstring = format!("Module Python {}", rel_path);
    file_bubble.lines_count = content.lines().count();
    file_bubble.complexity = compute_complexity(content);
    file_bubble.metadata.lines = file_bubble.lines_count;
    file_bubble.metadata.file_type = "python".to_string();
    nodes.push(file_bubble);

    // 1. Python Imports
    for cap in re_py_import().captures_iter(content) {
        if let Some(from_mod) = cap.get(1) {
            let mod_name = from_mod.as_str().replace('.', "/");
            calls.push(RawCall {
                caller: file_node_id.clone(),
                callee: mod_name.clone(),
                relation: "imports".to_string(),
                order_label: format!("Import {}", mod_name),
            });
            if let Some(imported_syms) = cap.get(2) {
                for sym in imported_syms.as_str().split(',') {
                    let clean = sym.trim();
                    if !clean.is_empty() && clean != "*" {
                        calls.push(RawCall {
                            caller: file_node_id.clone(),
                            callee: clean.to_string(),
                            relation: "imports".to_string(),
                            order_label: format!("Import {}", clean),
                        });
                    }
                }
            }
        } else if let Some(direct_imp) = cap.get(3) {
            for imp in direct_imp.as_str().split(',') {
                let clean = imp.split(" as ").next().unwrap_or("").trim();
                if !clean.is_empty() {
                    calls.push(RawCall {
                        caller: file_node_id.clone(),
                        callee: clean.to_string(),
                        relation: "imports".to_string(),
                        order_label: format!("Import {}", clean),
                    });
                }
            }
        }
    }

    // 2. Classes
    for cap in re_py_class().captures_iter(content) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(content, match_0.start());
        let bases_str = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let bases: Vec<String> = bases_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "object")
            .collect();

        let node_id = format!("{}::{}", rel_path, name);
        let layer = detect_layer(rel_path, name);
        let stereo = detect_stereotype(name, true, &layer, &bases);

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        for b in &bases {
            calls.push(RawCall {
                caller: node_id.clone(),
                callee: b.clone(),
                relation: "inherits".to_string(),
                order_label: format!("Hérite de {}", b),
            });
        }

        let body_slice = safe_slice(content, match_0.end(), 1500);
        let mut attributes = Vec::new();
        for f_cap in re_py_field().captures_iter(body_slice) {
            let f_name = f_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let f_type = f_cap.get(2).map(|m| m.as_str().trim().to_string());
            if !f_name.is_empty() && f_name != "def" && f_name != "class" {
                attributes.push(AstAttribute {
                    name: f_name.to_string(),
                    r#type: f_type,
                });
            }
        }

        let mut class_bubble = SymbolBubble::new(
            node_id,
            name.to_string(),
            rel_path.to_string(),
            line_no,
            SymbolKind::ClassOrStruct,
            galaxy.clone(),
            layer,
        );
        class_bubble.folder = folder.clone();
        class_bubble.stereotype = stereo;
        class_bubble.complexity = compute_complexity(body_slice);
        class_bubble.metadata.attributes = attributes;
        let py_class_doc = extract_python_docstring(body_slice);
        class_bubble.docstring = if !py_class_doc.is_empty() {
            py_class_doc
        } else {
            extract_leading_doc(content, match_0.start(), false)
        };
        nodes.push(class_bubble);
    }

    // 3. Functions
    for cap in re_py_func().captures_iter(content) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() || name.starts_with('_') {
            continue;
        }
        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(content, match_0.start());
        let body_slice = safe_slice(content, match_0.end(), 3000);

        let node_id = format!("{}::{}", rel_path, name);
        let layer = detect_layer(rel_path, name);
        let stereo = detect_stereotype(name, false, &layer, &[]);

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        for c_cap in re_call_ident().captures_iter(body_slice) {
            let callee = c_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if !callee.is_empty() && callee != name && !is_py_keyword(callee) {
                calls.push(RawCall {
                    caller: node_id.clone(),
                    callee: callee.to_string(),
                    relation: "calls".to_string(),
                    order_label: format!("Appel {}", callee),
                });
            }
        }

        for r_cap in re_py_route_str().captures_iter(body_slice) {
            if let Some(ep) = r_cap.get(1) {
                if galaxy == "client" {
                    routes_called.push((ep.as_str().to_string(), node_id.clone()));
                } else {
                    routes_declared.push((ep.as_str().to_string(), node_id.clone()));
                }
            }
        }

        let mut fn_bubble = SymbolBubble::new(
            node_id,
            name.to_string(),
            rel_path.to_string(),
            line_no,
            SymbolKind::Function,
            galaxy.clone(),
            layer,
        );
        fn_bubble.folder = folder.clone();
        fn_bubble.stereotype = stereo;
        fn_bubble.complexity = compute_complexity(body_slice);
        let py_fn_doc = extract_python_docstring(body_slice);
        let fn_doc = if !py_fn_doc.is_empty() {
            py_fn_doc
        } else {
            extract_leading_doc(content, match_0.start(), false)
        };
        fn_bubble.docstring = fn_doc.clone();
        fn_bubble.metadata.methods.push(AstMethod {
            name: name.to_string(),
            args: None,
            returns: None,
            is_async: Some(match_0.as_str().contains("async ")),
            calls: Vec::new(),
            docstring: if fn_doc.is_empty() { None } else { Some(fn_doc) },
        });
        nodes.push(fn_bubble);
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
