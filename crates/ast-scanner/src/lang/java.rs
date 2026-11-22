use core_graph::bubble::{AstAttribute, AstMethod, SymbolBubble, SymbolKind};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use crate::scanner::{
    compute_complexity, detect_galaxy, detect_layer, detect_stereotype, extract_fn_body_slice,
    extract_leading_doc, folder_from_rel_path, line_number_at, safe_slice, FileAnalysis, RawCall,
};

static_regex!(
    re_java_import,
    r#"import\s+(?:static\s+)?([A-Za-z0-9_.]+)(?:\.\*)?\s*;"#
);
static_regex!(
    re_java_class,
    r#"(?:^|\n)\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|protected|private|abstract|final|static|sealed|non-sealed)\s+)*(class|interface|enum|record|@interface)\s+([A-Za-z0-9_]+)(?:<[^>]*>)?(?:\([^)]*\))?(?:\s+extends\s+([A-Za-z0-9_.,\s<>]+?))?(?:\s+implements\s+([A-Za-z0-9_.,\s<>]+?))?\s*\{"#
);
static_regex!(
    re_java_field,
    r#"(?:^|\n)\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|protected|private|static|final|transient|volatile)\s+)+([A-Za-z0-9_<>\[\],\s]+?)\s+([A-Za-z0-9_]+)\s*(?:=[^;]+)?;"#
);
static_regex!(
    re_java_method,
    r#"(?:^|\n)\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|protected|private|static|final|abstract|synchronized|native|default)\s+)*(?:<[^>]*>\s+)?(?:([A-Za-z0-9_<>\[\]]+)\s+)?([A-Za-z0-9_]+)\s*\(([^)]*)\)(?:\s*throws\s+[A-Za-z0-9_.,\s]+)?\s*\{"#
);
static_regex!(
    re_java_call,
    r#"(?:\.|\b)([A-Za-z0-9_]+)\s*\("#
);
static_regex!(
    re_java_route,
    r#"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(\s*(?:(?:value|path)\s*=\s*)?["']([^"']+)["'])?"#
);
static_regex!(
    re_java_mc_event,
    r#"@EventHandler\b"#
);

fn is_java_keyword(word: &str) -> bool {
    matches!(
        word,
        "abstract" | "assert" | "boolean" | "break" | "byte" | "case" | "catch"
            | "char" | "class" | "const" | "continue" | "default" | "do" | "double"
            | "else" | "enum" | "extends" | "final" | "finally" | "float" | "for"
            | "goto" | "if" | "implements" | "import" | "instanceof" | "int"
            | "interface" | "long" | "native" | "new" | "package" | "private"
            | "protected" | "public" | "return" | "short" | "static" | "strictfp"
            | "super" | "switch" | "synchronized" | "this" | "throw" | "throws"
            | "transient" | "try" | "void" | "volatile" | "while" | "record"
            | "sealed" | "permits" | "yield" | "var"
    )
}

pub(crate) fn analyze_java(rel_path: &str, content: &str) -> FileAnalysis {
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
    file_bubble.docstring = format!("Fichier source Java {}", rel_path);
    file_bubble.lines_count = content.lines().count();
    file_bubble.complexity = compute_complexity(content);
    file_bubble.metadata.lines = file_bubble.lines_count;
    file_bubble.metadata.file_type = "java".to_string();
    nodes.push(file_bubble);

    // 1. Java Imports
    for cap in re_java_import().captures_iter(content) {
        if let Some(target) = cap.get(1) {
            let full_import = target.as_str().trim();
            let short_name = full_import.rsplit('.').next().unwrap_or(full_import);
            if !short_name.is_empty() && short_name != "*" {
                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: short_name.to_string(),
                    relation: "imports".to_string(),
                    order_label: format!("Import {}", full_import),
                });
            }
        }
    }

    // 2. Java Classes / Interfaces / Records / Enums
    for cap in re_java_class().captures_iter(content) {
        let kind_str = cap.get(1).map(|m| m.as_str()).unwrap_or("class");
        let name = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() || is_java_keyword(name) {
            continue;
        }
        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(content, match_0.start());
        let extends_str = cap.get(3).map(|m| m.as_str()).unwrap_or("");
        let implements_str = cap.get(4).map(|m| m.as_str()).unwrap_or("");

        let mut bases: Vec<String> = Vec::new();
        if !extends_str.is_empty() {
            for ext in extends_str.split(',') {
                let clean = ext.split('<').next().unwrap_or(ext).trim();
                let short = clean.rsplit('.').next().unwrap_or(clean).trim();
                if !short.is_empty() && !is_java_keyword(short) {
                    bases.push(short.to_string());
                }
            }
        }
        if !implements_str.is_empty() {
            for imp in implements_str.split(',') {
                let clean = imp.split('<').next().unwrap_or(imp).trim();
                let short = clean.rsplit('.').next().unwrap_or(clean).trim();
                if !short.is_empty() && !is_java_keyword(short) {
                    bases.push(short.to_string());
                }
            }
        }

        let node_id = format!("{}::{}", rel_path, name);
        let layer = detect_layer(rel_path, name);
        let mut stereo = detect_stereotype(name, true, &layer, &bases);
        if kind_str == "interface" && stereo == "«Class»" {
            stereo = "«Interface»".to_string();
        } else if kind_str == "enum" {
            stereo = "«Enum»".to_string();
        } else if kind_str == "record" {
            stereo = "«Record»".to_string();
        }

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

        let after_slice = safe_slice(content, match_0.end(), 12000);
        let mut attributes = Vec::new();

        for f_cap in re_java_field().captures_iter(after_slice) {
            let f_type = f_cap.get(1).map(|m| m.as_str().trim().to_string());
            let f_name = f_cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            if !f_name.is_empty() && !is_java_keyword(f_name) {
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
        class_bubble.complexity = 1 + (attributes.len() as u32 / 2);
        class_bubble.docstring = extract_leading_doc(content, match_0.start(), false);
        class_bubble.metadata.attributes = attributes;
        nodes.push(class_bubble);
    }

    // 3. Java Methods & Endpoints
    let mut seen_methods = HashSet::new();
    for cap in re_java_method().captures_iter(content) {
        let ret_type = cap.get(1).map(|m| m.as_str().trim().to_string());
        let name = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        if name.is_empty() || is_java_keyword(name) {
            continue;
        }

        let node_id = format!("{}::{}", rel_path, name);
        if !seen_methods.insert(node_id.clone()) {
            continue;
        }

        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(content, match_0.start());
        let args_str = cap.get(3).map(|m| m.as_str().trim().to_string());

        let leading_doc = extract_leading_doc(content, match_0.start(), false);
        let prefix_slice = if match_0.start() > 200 {
            safe_slice(content, match_0.start() - 200, 200)
        } else {
            safe_slice(content, 0, match_0.start())
        };

        let is_mc_event = match_0.as_str().contains("@EventHandler") || re_java_mc_event().is_match(prefix_slice);
        let route_cap = re_java_route().captures(match_0.as_str()).or_else(|| re_java_route().captures(prefix_slice));

        let layer = detect_layer(rel_path, name);
        let mut stereo = detect_stereotype(name, false, &layer, &[]);

        let is_endpoint = route_cap.is_some();
        if is_mc_event {
            stereo = "«Event Listener»".to_string();
        } else if is_endpoint {
            stereo = "«Endpoint»".to_string();
            if let Some(rc) = route_cap {
                let verb = rc.get(1).map(|m| m.as_str()).unwrap_or("Route");
                let path_val = rc.get(2).map(|m| m.as_str()).unwrap_or("");
                routes_declared.push((format!("{}: {}", verb, path_val), node_id.clone()));
            }
        }

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        let body_slice = extract_fn_body_slice(content, match_0.end(), 4000);
        let mut method_calls = Vec::new();

        for c_cap in re_java_call().captures_iter(body_slice) {
            let callee = c_cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            if !callee.is_empty()
                && callee != name
                && !is_java_keyword(callee)
                && callee != "System"
                && callee != "out"
                && callee != "println"
                && callee != "print"
                && !method_calls.contains(&callee.to_string()) {
                    method_calls.push(callee.to_string());
                    calls.push(RawCall {
                        caller: node_id.clone(),
                        callee: callee.to_string(),
                        relation: "calls".to_string(),
                        order_label: format!("Appel {}", callee),
                    });
                }
        }

        let kind = if is_endpoint {
            SymbolKind::FormOrEndpoint
        } else {
            SymbolKind::Function
        };

        let mut fn_bubble = SymbolBubble::new(
            node_id.clone(),
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
        fn_bubble.docstring = leading_doc.clone();
        fn_bubble.metadata.methods.push(AstMethod {
            name: name.to_string(),
            args: args_str,
            returns: ret_type,
            is_async: Some(false),
            calls: method_calls,
            docstring: if leading_doc.is_empty() { None } else { Some(leading_doc) },
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
