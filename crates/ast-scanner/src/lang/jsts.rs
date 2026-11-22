use core_graph::bubble::{AstAttribute, AstMethod, SymbolBubble, SymbolKind};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use super::re_call_ident;
use crate::scanner::{
    compute_complexity, detect_galaxy, detect_layer, detect_stereotype, extract_leading_doc,
    folder_from_rel_path, line_number_at, normalize_path, safe_slice, FileAnalysis, RawCall,
};

static_regex!(
    re_js_import,
    r#"import\s+(?:(\{[^}]+\})|([A-Za-z0-9_]+)|\*\s+as\s+([A-Za-z0-9_]+))?\s*(?:from\s*)?['"]([^'"]+)['"]"#
);
static_regex!(re_js_require, r#"require\s*\(\s*['"]([^'"]+)['"]\s*\)"#);
static_regex!(
    re_js_class,
    r#"(?:export\s+)?(?:class|interface)\s+([A-Za-z0-9_]+)(?:\s+extends\s+([A-Za-z0-9_]+))?"#
);
static_regex!(
    re_js_func,
    r#"(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)"#
);
static_regex!(
    re_js_arrow,
    r#"(?:export\s+)?const\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"#
);
static_regex!(re_jsx_tag, r#"<([A-Z][A-Za-z0-9_]+)"#);
static_regex!(
    re_js_network,
    r#"(?:fetch|axios\.(?:get|post|put|delete|patch)|api(?:Client)?\.(?:get|post|put|delete))\s*\(\s*['"`]([^'"`]+)['"`]"#
);
static_regex!(re_js_submit, r#"onSubmit\s*=\s*\{\s*([A-Za-z0-9_]+)"#);
static_regex!(re_js_hook, r#"(use[A-Z][A-Za-z0-9_]*)"#);
static_regex!(re_js_ws_emit, r#"socket\.emit\(['"`]([^'"`]+)['"`]"#);

fn is_js_keyword(word: &str) -> bool {
    matches!(
        word,
        "if" | "for"
            | "while"
            | "switch"
            | "catch"
            | "return"
            | "require"
            | "import"
            | "function"
            | "const"
            | "let"
            | "var"
            | "throw"
            | "typeof"
            | "instanceof"
            | "new"
            | "case"
            | "default"
            | "super"
    )
}

pub(crate) fn analyze_jsts(rel_path: &str, content: &str) -> FileAnalysis {
    let mut nodes = Vec::new();
    let mut calls = Vec::new();
    let mut routes_declared = Vec::new();
    let mut routes_called = Vec::new();
    let ws_handlers = Vec::new();
    let mut ws_emits = Vec::new();

    let is_react = rel_path.ends_with(".jsx")
        || rel_path.ends_with(".tsx")
        || content.contains("React")
        || content.contains("useState");

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
    file_bubble.docstring = format!("Fichier source {}", rel_path);
    file_bubble.lines_count = content.lines().count();
    file_bubble.complexity = compute_complexity(content);
    file_bubble.metadata.lines = file_bubble.lines_count;
    file_bubble.metadata.file_type = if is_react {
        "react".to_string()
    } else {
        "javascript".to_string()
    };
    nodes.push(file_bubble);

    let cur_dir = Path::new(rel_path)
        .parent()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();

    // 1. ES6 Imports
    for cap in re_js_import().captures_iter(content) {
        if let Some(target_match) = cap.get(4) {
            let target_path = target_match.as_str();
            if target_path.starts_with('.') {
                let joined = if cur_dir.is_empty() {
                    target_path.to_string()
                } else {
                    format!("{}/{}", cur_dir, target_path)
                };
                let norm = normalize_path(&joined);
                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: norm,
                    relation: "imports".to_string(),
                    order_label: "Import".to_string(),
                });
            } else {
                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: target_path.to_string(),
                    relation: "imports".to_string(),
                    order_label: format!("Import {}", target_path),
                });
            }

            if let Some(named_match) = cap.get(1) {
                let inner = named_match.as_str().trim_matches(|c| c == '{' || c == '}');
                for sym in inner.split(',') {
                    let clean = sym.split(" as ").next().unwrap_or("").trim();
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
    }

    // CommonJS require('...')
    for cap in re_js_require().captures_iter(content) {
        if let Some(m) = cap.get(1) {
            let target_path = m.as_str();
            if target_path.starts_with('.') {
                let joined = if cur_dir.is_empty() {
                    target_path.to_string()
                } else {
                    format!("{}/{}", cur_dir, target_path)
                };
                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: normalize_path(&joined),
                    relation: "imports".to_string(),
                    order_label: "Require".to_string(),
                });
            }
        }
    }

    // 2. Classes & Interfaces
    for cap in re_js_class().captures_iter(content) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let extends = cap.get(2).map(|m| m.as_str().to_string());
        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(content, match_0.start());
        let class_slice = safe_slice(content, match_0.end(), 2500);

        let node_id = format!("{}::{}", rel_path, name);
        let layer = detect_layer(rel_path, name);
        let bases = extends.clone().map(|e| vec![e]).unwrap_or_default();
        let stereo = detect_stereotype(name, true, &layer, &bases);

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        if let Some(ref ext) = extends {
            calls.push(RawCall {
                caller: node_id.clone(),
                callee: ext.clone(),
                relation: "inherits".to_string(),
                order_label: format!("Hérite de {}", ext),
            });
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
        class_bubble.complexity = compute_complexity(class_slice);
        class_bubble.docstring = extract_leading_doc(content, match_0.start(), false);
        nodes.push(class_bubble);
    }

    // 3. Functions & React Components
    let mut seen_fn_ids = HashSet::new();

    for cap in re_js_func()
        .captures_iter(content)
        .chain(re_js_arrow().captures_iter(content))
    {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let node_id = format!("{}::{}", rel_path, name);
        if !seen_fn_ids.insert(node_id.clone()) {
            continue;
        }

        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(content, match_0.start());
        let body_slice = safe_slice(content, match_0.end(), 6000);

        let is_comp =
            name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) && is_react;
        let is_form = name.to_lowercase().contains("form")
            || body_slice.contains("<form")
            || body_slice.contains("onSubmit")
            || body_slice.contains("handleSubmit")
            || body_slice.contains("useForm");

        let layer = if is_comp {
            "ui".to_string()
        } else {
            detect_layer(rel_path, name)
        };
        let stereo = if is_form {
            "«Form»".to_string()
        } else if is_comp {
            "«Component»".to_string()
        } else {
            detect_stereotype(name, false, &layer, &[])
        };

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        for c_cap in re_call_ident().captures_iter(body_slice) {
            let callee = c_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if !callee.is_empty() && callee != name && !is_js_keyword(callee) {
                calls.push(RawCall {
                    caller: node_id.clone(),
                    callee: callee.to_string(),
                    relation: "calls".to_string(),
                    order_label: format!("Appel {}", callee),
                });
            }
        }

        for j_cap in re_jsx_tag().captures_iter(body_slice) {
            let rendered = j_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if !rendered.is_empty() && rendered != name {
                calls.push(RawCall {
                    caller: node_id.clone(),
                    callee: rendered.to_string(),
                    relation: "renders".to_string(),
                    order_label: format!("Rend <{}/>", rendered),
                });
            }
        }

        for net_cap in re_js_network().captures_iter(body_slice) {
            if let Some(endpoint) = net_cap.get(1) {
                let ep = endpoint.as_str().trim();
                if !ep.is_empty() {
                    calls.push(RawCall {
                        caller: node_id.clone(),
                        callee: ep.to_string(),
                        relation: "network".to_string(),
                        order_label: format!("Réseau {}", ep),
                    });
                    routes_called.push((ep.to_string(), node_id.clone()));
                }
            }
        }

        for sub_cap in re_js_submit().captures_iter(body_slice) {
            if let Some(handler) = sub_cap.get(1) {
                let h_name = handler.as_str();
                if h_name != name {
                    calls.push(RawCall {
                        caller: node_id.clone(),
                        callee: h_name.to_string(),
                        relation: "submits".to_string(),
                        order_label: format!("Soumet {}", h_name),
                    });
                }
            }
        }

        for ws_cap in re_js_ws_emit().captures_iter(body_slice) {
            if let Some(pkt) = ws_cap.get(1) {
                ws_emits.push((pkt.as_str().to_string(), node_id.clone()));
            }
        }

        if galaxy == "server" && (name.to_lowercase().contains("handle") || name.to_lowercase().contains("route") || rel_path.contains("api")) {
            routes_declared.push((name.to_string(), node_id.clone()));
        }

        let mut comp_attrs = Vec::new();
        for h_cap in re_js_hook().captures_iter(body_slice) {
            if let Some(h) = h_cap.get(1) {
                let h_name = h.as_str();
                if !comp_attrs.iter().any(|a: &AstAttribute| a.name == h_name) {
                    comp_attrs.push(AstAttribute {
                        name: h_name.to_string(),
                        r#type: Some("Hook".to_string()),
                    });
                }
            }
        }

        let kind = if is_form {
            SymbolKind::FormOrEndpoint
        } else {
            SymbolKind::Function
        };
        let mut fn_bubble = SymbolBubble::new(
            node_id,
            name.to_string(),
            rel_path.to_string(),
            line_no,
            kind,
            galaxy.clone(),
            layer,
        );
        fn_bubble.folder = folder.clone();
        fn_bubble.stereotype = stereo;
        fn_bubble.complexity = compute_complexity(body_slice);
        let fn_doc = extract_leading_doc(content, match_0.start(), false);
        fn_bubble.docstring = fn_doc.clone();
        fn_bubble.symbol_type = if is_form {
            "form".to_string()
        } else if is_comp {
            "component".to_string()
        } else {
            "function".to_string()
        };
        fn_bubble.metadata.attributes = comp_attrs;
        fn_bubble.metadata.methods.push(AstMethod {
            name: name.to_string(),
            args: None,
            returns: None,
            is_async: Some(match_0.as_str().contains("async")),
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
