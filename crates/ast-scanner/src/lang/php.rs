use core_graph::bubble::{AstMethod, SymbolBubble, SymbolKind};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

use crate::scanner::{
    compute_complexity, detect_galaxy, detect_layer, detect_stereotype, extract_leading_doc,
    folder_from_rel_path, line_number_at, safe_slice, FileAnalysis, RawCall,
};

static_regex!(
    re_php_use,
    r#"use\s+([A-Za-z0-9_\\]+)(?:\s+as\s+([A-Za-z0-9_]+))?\s*;"#
);
static_regex!(
    re_php_class,
    r#"(?:^|\n)\s*(?:(?:abstract|final|readonly)\s+)?(?:class|interface|trait|enum)\s+([A-Za-z0-9_]+)(?:\s+extends\s+([A-Za-z0-9_\\]+))?(?:\s+implements\s+([^{]+))?"#
);
static_regex!(
    re_php_func,
    r#"(?:^|\n)\s*(?:(?:public|protected|private|static|final|abstract|readonly)\s+)*function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)(?:\s*:\s*([A-Za-z0-9_\\?|&]+))?"#
);
static_regex!(
    re_php_call,
    r#"(?:->|::|\b)([A-Za-z0-9_]+)\s*\("#
);
static_regex!(
    re_php_route,
    r#"#\[Route\(['"]([^'"]+)['"]|\$(?:app|router|route)->(?:get|post|put|delete|patch)\(['"]([^'"]+)['"]|Route::(?:get|post|put|delete|patch)\(['"]([^'"]+)['"]"#
);

pub(crate) fn analyze_php(rel_path: &str, content: &str) -> FileAnalysis {
    let mut nodes = Vec::new();
    let mut calls = Vec::new();
    let mut routes_declared = Vec::new();
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
    file_bubble.docstring = format!("Module / Script PHP {}", rel_path);
    file_bubble.lines_count = content.lines().count();
    file_bubble.complexity = compute_complexity(content);
    file_bubble.metadata.lines = file_bubble.lines_count;
    file_bubble.metadata.file_type = "php".to_string();
    nodes.push(file_bubble);

    // 1. PHP use imports
    for cap in re_php_use().captures_iter(content) {
        if let Some(target) = cap.get(1) {
            let full_import = target.as_str().trim();
            let short_name = cap
                .get(2)
                .map(|m| m.as_str().trim())
                .unwrap_or_else(|| full_import.rsplit('\\').next().unwrap_or(full_import));
            calls.push(RawCall {
                caller: file_node_id.clone(),
                callee: short_name.to_string(),
                relation: "imports".to_string(),
                order_label: format!("Import {}", full_import),
            });
        }
    }

    // 2. PHP Classes / Interfaces / Traits
    for cap in re_php_class().captures_iter(content) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(content, match_0.start());
        let extends_str = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let implements_str = cap.get(3).map(|m| m.as_str()).unwrap_or("");

        let mut bases: Vec<String> = Vec::new();
        if !extends_str.is_empty() {
            let clean = extends_str.rsplit('\\').next().unwrap_or(extends_str).trim();
            if !clean.is_empty() {
                bases.push(clean.to_string());
            }
        }
        if !implements_str.is_empty() {
            for imp in implements_str.split(',') {
                let clean = imp.trim().rsplit('\\').next().unwrap_or(imp).trim();
                if !clean.is_empty() {
                    bases.push(clean.to_string());
                }
            }
        }

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

        let mut class_bubble = SymbolBubble::new(
            node_id.clone(),
            name.to_string(),
            rel_path.to_string(),
            line_no,
            SymbolKind::ClassOrStruct,
            galaxy.clone(),
            layer,
        );
        class_bubble.folder = folder.clone();
        class_bubble.stereotype = stereo;
        let class_doc = extract_leading_doc(content, match_0.start(), false);
        class_bubble.docstring = class_doc;
        class_bubble.complexity = 1;
        nodes.push(class_bubble);
    }

    // 3. PHP Functions & Methods
    for cap in re_php_func().captures_iter(content) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(content, match_0.start());
        let args_str = cap.get(2).map(|m| m.as_str().trim().to_string());
        let ret_str = cap.get(3).map(|m| m.as_str().trim().to_string());

        let node_id = format!("{}::{}", rel_path, name);
        let layer = detect_layer(rel_path, name);
        let stereo = detect_stereotype(name, false, &layer, &[]);

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        let body_slice = safe_slice(content, match_0.end(), 2000);
        for c_cap in re_php_call().captures_iter(body_slice) {
            let callee = c_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if !callee.is_empty() && callee != name && callee != "function" && callee != "echo" && callee != "print" {
                calls.push(RawCall {
                    caller: node_id.clone(),
                    callee: callee.to_string(),
                    relation: "calls".to_string(),
                    order_label: format!("Appel {}", callee),
                });
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
        let fn_doc = extract_leading_doc(content, match_0.start(), false);
        fn_bubble.docstring = fn_doc.clone();
        fn_bubble.metadata.methods.push(AstMethod {
            name: name.to_string(),
            args: args_str,
            returns: ret_str,
            is_async: None,
            calls: Vec::new(),
            docstring: if fn_doc.is_empty() { None } else { Some(fn_doc) },
        });
        nodes.push(fn_bubble);
    }

    // 4. PHP Routes
    for cap in re_php_route().captures_iter(content) {
        if let Some(r_path) = cap.get(1).or_else(|| cap.get(2)).or_else(|| cap.get(3)) {
            let p_str = r_path.as_str().trim();
            if !p_str.is_empty() {
                routes_declared.push((p_str.to_string(), file_node_id.clone()));
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
        ws_handlers,
        ws_emits,
    }
}
