use core_graph::bubble::{AstAttribute, AstMethod, SymbolBubble, SymbolKind};
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use super::re_call_ident;
use crate::scanner::{
    compute_complexity, detect_galaxy, detect_layer, detect_stereotype, extract_fn_body_slice,
    extract_leading_doc, folder_from_rel_path, line_number_at, safe_slice, FileAnalysis, RawCall,
};

static_regex!(
    re_rs_mod,
    r#"(?:^|\n)\s*(?:pub\s+)?mod\s+([a-zA-Z0-9_]+)\s*;"#
);
static_regex!(re_rs_use, r#"(?:^|\n)\s*(?:pub\s+)?use\s+([^;]+);"#);
static_regex!(
    re_rs_struct,
    r#"(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait)\s+([A-Za-z0-9_]+)"#
);
static_regex!(
    re_rs_field,
    r#"(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?([a-z0-9_]+)\s*:\s*([^,\n}]+)"#
);
static_regex!(
    re_rs_impl_trait,
    r#"(?:^|\n)\s*impl(?:<[^>]*>)?\s+([A-Za-z0-9_:]+)\s+for\s+([A-Za-z0-9_]+)"#
);
static_regex!(
    re_rs_fn,
    r#"(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([a-zA-Z0-9_]+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)(?:\s*->\s*([^{;\n]+))?"#
);
static_regex!(re_rs_qual_call, r#"\b([A-Za-z0-9_]+)::([a-zA-Z0-9_]+)\s*\("#);
static_regex!(
    re_rs_route,
    r#"fetch\(['"`]([^'"`]+)['"`]|route\(\s*['"`]([^'"`]+)['"`]"#
);
static_regex!(
    re_rs_ws,
    r#"(ClientPacket::[A-Za-z0-9_]+|ServerPacket::[A-Za-z0-9_]+)"#
);

fn is_rust_keyword(word: &str) -> bool {
    matches!(
        word,
        "if" | "match"
            | "for"
            | "while"
            | "loop"
            | "return"
            | "Some"
            | "None"
            | "Ok"
            | "Err"
            | "Box"
            | "Vec"
            | "String"
            | "Arc"
            | "Mutex"
            | "RwLock"
            | "HashMap"
            | "HashSet"
            | "BTreeMap"
            | "BTreeSet"
            | "VecDeque"
            | "Path"
            | "PathBuf"
            | "Duration"
            | "Instant"
            | "Option"
            | "Result"
            | "format"
            | "println"
            | "eprintln"
            | "write"
            | "writeln"
            | "vec"
            | "Default"
            | "default"
            | "new"
            | "with_capacity"
            | "from"
            | "into"
            | "clone"
            | "cloned"
            | "copied"
            | "unwrap"
            | "expect"
            | "map"
            | "map_err"
            | "and_then"
            | "or_else"
            | "ok_or"
            | "ok_or_else"
            | "unwrap_or"
            | "unwrap_or_else"
            | "unwrap_or_default"
            | "collect"
            | "iter"
            | "iter_mut"
            | "into_iter"
            | "par_iter"
            | "to_string"
            | "to_owned"
            | "to_lowercase"
            | "to_uppercase"
            | "to_string_lossy"
            | "as_str"
            | "as_ref"
            | "as_mut"
            | "as_bytes"
            | "as_slice"
            | "as_deref"
            | "len"
            | "is_empty"
            | "push"
            | "push_str"
            | "pop"
            | "insert"
            | "remove"
            | "get"
            | "get_mut"
            | "entry"
            | "or_insert"
            | "or_insert_with"
            | "or_default"
            | "contains"
            | "contains_key"
            | "starts_with"
            | "ends_with"
            | "find"
            | "rfind"
            | "split"
            | "trim"
            | "trim_start"
            | "trim_end"
            | "trim_matches"
            | "trim_start_matches"
            | "trim_end_matches"
            | "replace"
            | "lines"
            | "bytes"
            | "chars"
            | "filter"
            | "filter_map"
            | "any"
            | "all"
            | "enumerate"
            | "take"
            | "skip"
            | "rev"
            | "count"
            | "ok"
            | "err"
            | "is_ok"
            | "is_err"
            | "is_some"
            | "is_none"
            | "min"
            | "max"
            | "clamp"
            | "saturating_sub"
            | "saturating_add"
            | "checked_sub"
            | "checked_add"
            | "lock"
            | "read"
            | "try_recv"
            | "join"
            | "strip_prefix"
            | "extension"
            | "file_name"
            | "file_stem"
            | "parent"
            | "exists"
            | "is_dir"
            | "is_file"
    )
}

pub(crate) fn analyze_rust(rel_path: &str, content: &str) -> FileAnalysis {
    let mut nodes = Vec::new();
    let mut calls = Vec::new();
    let mut routes_declared = Vec::new();
    let mut routes_called = Vec::new();
    let mut ws_handlers = Vec::new();
    let mut ws_emits = Vec::new();

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
    file_bubble.docstring = format!("Module Rust {}", rel_path);
    file_bubble.lines_count = content.lines().count();
    file_bubble.complexity = compute_complexity(content);
    file_bubble.metadata.lines = file_bubble.lines_count;
    file_bubble.metadata.file_type = "rust".to_string();
    nodes.push(file_bubble);

    // Strip inline #[cfg(test)] unit test blocks from architectural AST symbols
    let prod_content = content
        .find("\n#[cfg(test)]")
        .or_else(|| content.find("\r\n#[cfg(test)]"))
        .map(|idx| &content[..idx])
        .unwrap_or(content);

    // 1. Rust `mod` & `use` declarations (cross-file & cross-crate links)
    for cap in re_rs_mod().captures_iter(prod_content) {
        if let Some(m) = cap.get(1) {
            let mod_name = m.as_str();
            calls.push(RawCall {
                caller: file_node_id.clone(),
                callee: mod_name.to_string(),
                relation: "imports".to_string(),
                order_label: format!("Mod {}", mod_name),
            });
        }
    }

    for cap in re_rs_use().captures_iter(prod_content) {
        if let Some(m) = cap.get(1) {
            let expr = m.as_str().trim();
            // Extract braced symbols if present: foo::bar::{A, B}
            if let Some(brace_start) = expr.find('{') {
                let prefix = expr[..brace_start].trim_end_matches(':');
                for seg in prefix.split("::") {
                    let s = seg.trim();
                    if !s.is_empty() && s != "crate" && s != "self" && s != "super" && s != "std" {
                        calls.push(RawCall {
                            caller: file_node_id.clone(),
                            callee: s.to_string(),
                            relation: "imports".to_string(),
                            order_label: format!("Use {}", s),
                        });
                    }
                }
                if let Some(brace_end) = expr.rfind('}') {
                    let inner = &expr[brace_start + 1..brace_end];
                    for item in inner.split(',') {
                        let clean = item.split(" as ").next().unwrap_or("").trim();
                        if !clean.is_empty() && clean != "*" && clean != "self" {
                            calls.push(RawCall {
                                caller: file_node_id.clone(),
                                callee: clean.to_string(),
                                relation: "imports".to_string(),
                                order_label: format!("Use {}", clean),
                            });
                        }
                    }
                }
            } else {
                for seg in expr.split("::") {
                    let clean = seg.split(" as ").next().unwrap_or("").trim();
                    if !clean.is_empty()
                        && clean != "*"
                        && clean != "crate"
                        && clean != "self"
                        && clean != "super"
                        && clean != "std"
                    {
                        calls.push(RawCall {
                            caller: file_node_id.clone(),
                            callee: clean.to_string(),
                            relation: "imports".to_string(),
                            order_label: format!("Use {}", clean),
                        });
                    }
                }
            }
        }
    }

    // 2. Rust Structs, Enums, Traits
    for cap in re_rs_struct().captures_iter(prod_content) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(prod_content, match_0.start());
        let node_id = format!("{}::{}", rel_path, name);
        let layer = detect_layer(rel_path, name);
        let stereo = detect_stereotype(name, true, &layer, &[]);

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        // Extract struct fields for UML card
        let mut attributes = Vec::new();
        let after_slice = safe_slice(prod_content, match_0.end(), 1500);
        if let Some(open_brace) = after_slice.find('{') {
            if open_brace < 120 {
                let body_end = after_slice[open_brace..]
                    .find('}')
                    .unwrap_or(after_slice.len() - open_brace);
                let struct_body = &after_slice[open_brace..open_brace + body_end];
                for f_cap in re_rs_field().captures_iter(struct_body) {
                    let f_name = f_cap.get(1).map(|m| m.as_str()).unwrap_or("");
                    let f_type = f_cap.get(2).map(|m| m.as_str().trim().to_string());
                    if !f_name.is_empty() {
                        attributes.push(AstAttribute {
                            name: f_name.to_string(),
                            r#type: f_type,
                        });
                    }
                }
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
        class_bubble.docstring = extract_leading_doc(prod_content, match_0.start(), true);
        nodes.push(class_bubble);
    }

    // Trait implementations -> inherits edge
    for cap in re_rs_impl_trait().captures_iter(prod_content) {
        let trait_name = cap
            .get(1)
            .map(|m| m.as_str().split("::").last().unwrap_or(m.as_str()))
            .unwrap_or("");
        let struct_name = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        if !trait_name.is_empty() && !struct_name.is_empty() {
            calls.push(RawCall {
                caller: format!("{}::{}", rel_path, struct_name),
                callee: trait_name.to_string(),
                relation: "inherits".to_string(),
                order_label: format!("Implémente {}", trait_name),
            });
        }
    }

    // 3. Rust Functions (`fn ...`)
    for cap in re_rs_fn().captures_iter(prod_content) {
        let name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() || name.starts_with("test_") || (name == "main" && rel_path.contains("build.rs")) {
            continue;
        }
        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(prod_content, match_0.start());
        let args_str = cap.get(2).map(|m| m.as_str().trim().to_string());
        let ret_str = cap.get(3).map(|m| m.as_str().trim().to_string());
        let body_slice = extract_fn_body_slice(prod_content, match_0.end(), 3500);

        let node_id = format!("{}::{}", rel_path, name);
        let layer = detect_layer(rel_path, name);
        let stereo = detect_stereotype(name, false, &layer, &[]);

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        let mut seen_local_calls: HashSet<String> = HashSet::new();

        for q_cap in re_rs_qual_call().captures_iter(body_slice) {
            let prefix = q_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let method = q_cap.get(2).map(|m| m.as_str()).unwrap_or("");
            if !prefix.is_empty() && !is_rust_keyword(prefix) && prefix != "Self" && prefix != "std"
                && seen_local_calls.insert(prefix.to_string()) {
                    calls.push(RawCall {
                        caller: node_id.clone(),
                        callee: prefix.to_string(),
                        relation: "calls".to_string(),
                        order_label: format!("Appel {}::{}", prefix, method),
                    });
                }
            if !method.is_empty() && !is_rust_keyword(method)
                && seen_local_calls.insert(method.to_string()) {
                    calls.push(RawCall {
                        caller: node_id.clone(),
                        callee: method.to_string(),
                        relation: "calls".to_string(),
                        order_label: format!("Appel {}", method),
                    });
                }
        }

        for c_cap in re_call_ident().captures_iter(body_slice) {
            let callee = c_cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if !callee.is_empty() && callee != name && !is_rust_keyword(callee)
                && seen_local_calls.insert(callee.to_string()) {
                    calls.push(RawCall {
                        caller: node_id.clone(),
                        callee: callee.to_string(),
                        relation: "calls".to_string(),
                        order_label: format!("Appel {}", callee),
                    });
                }
        }

        for r_cap in re_rs_route().captures_iter(body_slice) {
            if let Some(m) = r_cap.get(1).or_else(|| r_cap.get(2)) {
                let ep = m.as_str().to_string();
                if galaxy == "client" {
                    routes_called.push((ep.clone(), node_id.clone()));
                } else {
                    routes_declared.push((ep.clone(), node_id.clone()));
                }
            }
        }

        if galaxy == "server" && (name.starts_with("handle_") || rel_path.contains("api")) {
            routes_declared.push((name.to_string(), node_id.clone()));
        }

        for ws_cap in re_rs_ws().captures_iter(body_slice) {
            if let Some(m) = ws_cap.get(1) {
                let pkt = m.as_str().to_string();
                if galaxy == "client" {
                    ws_emits.push((pkt, node_id.clone()));
                } else {
                    ws_handlers.push((pkt, node_id.clone()));
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
        let fn_doc = extract_leading_doc(prod_content, match_0.start(), true);
        fn_bubble.docstring = fn_doc.clone();
        fn_bubble.metadata.methods.push(AstMethod {
            name: name.to_string(),
            args: args_str,
            returns: ret_str,
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
