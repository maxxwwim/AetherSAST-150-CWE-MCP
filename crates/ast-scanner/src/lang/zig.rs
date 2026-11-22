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
    re_zig_import,
    r#"(?:const|var)\s+([A-Za-z0-9_]+)\s*=\s*@import\(\s*["']([^"']+)["']\s*\)"#
);
static_regex!(
    re_zig_cimport,
    r#"(?:const|var)\s+([A-Za-z0-9_]+)\s*=\s*@cImport\("#
);
static_regex!(
    re_zig_container,
    r#"(?:^|\n)\s*(?:pub\s+)?(?:const|var)\s+([A-Za-z0-9_]+)\s*=\s*(?:extern\s+|packed\s+)?(struct|enum|union(?:\([^)]*\))?|error|opaque)\s*\{"#
);
static_regex!(
    re_zig_field,
    r#"(?:^|\n)\s*([a-zA-Z0-9_]+)\s*:\s*([^,=;{}]+?)(?:\s*=\s*[^,;{}]+)?\s*,"#
);
static_regex!(
    re_zig_fn,
    r#"(?:^|\n)\s*(?:pub\s+)?(?:export\s+|extern\s+|inline\s+)?fn\s+([a-zA-Z0-9_]+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)\s*(?:(?:!\s*)?([^{;]+))?\s*\{"#
);
static_regex!(
    re_zig_call,
    r#"(?:\.|\b)([a-zA-Z0-9_]+)\s*\("#
);

fn is_zig_keyword(word: &str) -> bool {
    matches!(
        word,
        "fn" | "pub" | "const" | "var" | "struct" | "enum" | "union" | "error" | "opaque"
            | "try" | "catch" | "orelse" | "if" | "else" | "while" | "loop" | "switch"
            | "return" | "defer" | "errdefer" | "unreachable" | "break" | "continue"
            | "asm" | "inline" | "noinline" | "comptime" | "volatile" | "align"
            | "linksection" | "export" | "extern" | "threadlocal" | "usingnamespace"
            | "test" | "and" | "or" | "anytype" | "anyerror" | "null" | "undefined"
            | "true" | "false"
    )
}

pub fn strip_zig_inline_tests(content: &str) -> &str {
    let mut offset = 0usize;
    for line in content.split_inclusive('\n') {
        let trimmed = line.trim();
        if (trimmed.starts_with("test ") || trimmed.starts_with("test\""))
            && (trimmed.ends_with('{') || trimmed.contains('{') || trimmed.ends_with('"'))
        {
            return &content[..offset];
        }
        offset += line.len();
    }
    content
}

pub fn analyze_zig(rel_path: &str, content: &str) -> FileAnalysis {
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
    file_bubble.docstring = format!("Module Zig {}", rel_path);
    file_bubble.lines_count = content.lines().count();
    file_bubble.complexity = compute_complexity(content);
    file_bubble.metadata.lines = file_bubble.lines_count;
    file_bubble.metadata.file_type = "zig".to_string();
    nodes.push(file_bubble);

    // Strip inline tests so test declarations do not pollute production graph
    let prod_content = strip_zig_inline_tests(content);

    // 1. Imports (@import, @cImport)
    for cap in re_zig_import().captures_iter(prod_content) {
        let var_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let import_target = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        if !import_target.is_empty() {
            let match_0 = cap.get(0).unwrap();
            let line_no = line_number_at(prod_content, match_0.start());
            calls.push(RawCall {
                caller: file_node_id.clone(),
                callee: import_target.to_string(),
                relation: "imports".to_string(),
                order_label: format!("Import {}", import_target),
            });
            let imp_id = format!("import::{}::{}", rel_path, var_name);
            let mut imp_bubble = SymbolBubble::new(
                imp_id,
                var_name.to_string(),
                rel_path.to_string(),
                line_no,
                SymbolKind::Contract,
                galaxy.clone(),
                detect_layer(rel_path, "import"),
            );
            imp_bubble.folder = folder.clone();
            imp_bubble.stereotype = "«Import»".to_string();
            nodes.push(imp_bubble);
        }
    }

    for cap in re_zig_cimport().captures_iter(prod_content) {
        let var_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(prod_content, match_0.start());
        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: "cImport".to_string(),
            relation: "imports".to_string(),
            order_label: "cImport".to_string(),
        });
        if !var_name.is_empty() {
            let imp_id = format!("cimport::{}::{}", rel_path, var_name);
            let mut imp_bubble = SymbolBubble::new(
                imp_id,
                var_name.to_string(),
                rel_path.to_string(),
                line_no,
                SymbolKind::Contract,
                galaxy.clone(),
                detect_layer(rel_path, "import"),
            );
            imp_bubble.folder = folder.clone();
            imp_bubble.stereotype = "«Import»".to_string();
            nodes.push(imp_bubble);
        }
    }

    // 2. Containers: struct, enum, union, error, opaque
    for cap in re_zig_container().captures_iter(prod_content) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let container_type = cap.get(2).map(|m| m.as_str()).unwrap_or("struct");
        if name.is_empty() {
            continue;
        }

        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(prod_content, match_0.start());
        let node_id = format!("{}::{}", rel_path, name);
        let layer = detect_layer(rel_path, name);

        let stereo = if container_type.starts_with("struct") {
            detect_stereotype(name, true, &layer, &[])
        } else if container_type.starts_with("enum") {
            "«Enum»".to_string()
        } else if container_type.starts_with("union") {
            "«Union»".to_string()
        } else if container_type.starts_with("error") {
            "«ErrorSet»".to_string()
        } else if container_type.starts_with("opaque") {
            "«Opaque»".to_string()
        } else {
            "«Struct»".to_string()
        };

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        // Extract container fields
        let mut attributes = Vec::new();
        let after_slice = safe_slice(prod_content, match_0.end(), 3000);
        let body_end = after_slice.find('}').unwrap_or(after_slice.len());
        let container_body = &after_slice[..body_end];

        for f_cap in re_zig_field().captures_iter(container_body) {
            let f_name = f_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let f_type = f_cap.get(2).map(|m| m.as_str().trim().to_string());
            if !f_name.is_empty() && !is_zig_keyword(f_name) {
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
        class_bubble.complexity = (1 + attributes.len() as u32 / 2).max(1);
        class_bubble.metadata.attributes = attributes;
        class_bubble.docstring = extract_leading_doc(prod_content, match_0.start(), false);
        nodes.push(class_bubble);
    }

    // 3. Functions & Methods
    for cap in re_zig_fn().captures_iter(prod_content) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() || name.starts_with("test_") || is_zig_keyword(name) {
            continue;
        }

        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(prod_content, match_0.start());
        let args_str = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        let ret_str = cap.get(3).map(|m| m.as_str().trim().to_string());
        let body_slice = extract_fn_body_slice(prod_content, match_0.end(), 3500);

        let node_id = format!("{}::{}", rel_path, name);
        let layer = detect_layer(rel_path, name);

        // Check if method (receives self or *Self or &self)
        let is_method = args_str.contains("self:")
            || args_str.contains("self: *")
            || args_str.contains("self: *Self")
            || args_str.contains("self: Self")
            || args_str.contains("&self");

        let stereo = if is_method {
            "«Method»".to_string()
        } else {
            detect_stereotype(name, false, &layer, &[])
        };

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        // Parent container linking for method if self parameter specifies a type
        if is_method {
            if let Some(self_idx) = args_str.find("self:") {
                let after_self = &args_str[self_idx + 5..];
                let type_part = after_self.split(',').next().unwrap_or("").trim();
                let clean_type = type_part.trim_start_matches('*').trim();
                if !clean_type.is_empty() && clean_type != "Self" && !is_zig_keyword(clean_type) {
                    let parent_id = format!("{}::{}", rel_path, clean_type);
                    calls.push(RawCall {
                        caller: parent_id,
                        callee: node_id.clone(),
                        relation: "contains".to_string(),
                        order_label: "Méthode".to_string(),
                    });
                }
            }
        }

        let mut method_calls = Vec::new();
        let mut seen_local_calls = HashSet::new();

        for c_cap in re_zig_call().captures_iter(body_slice) {
            let callee = c_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if !callee.is_empty() && callee != name && !is_zig_keyword(callee)
                && seen_local_calls.insert(callee.to_string()) {
                    method_calls.push(callee.to_string());
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
        let fn_doc = extract_leading_doc(prod_content, match_0.start(), false);
        fn_bubble.docstring = fn_doc.clone();
        fn_bubble.metadata.methods.push(AstMethod {
            name: name.to_string(),
            args: if args_str.is_empty() { None } else { Some(args_str.to_string()) },
            returns: ret_str,
            is_async: Some(false),
            calls: method_calls,
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

pub fn analyze_zig_symbols(file_path: &Path, content: &str) -> Vec<SymbolBubble> {
    analyze_zig(&file_path.to_string_lossy().replace('\\', "/"), content).nodes
}
