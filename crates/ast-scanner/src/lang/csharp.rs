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
    re_cs_using,
    r#"(?:^|\n)\s*(?:global\s+)?using\s+(?:static\s+)?(?:([A-Za-z0-9_]+)\s*=\s*)?([A-Za-z0-9_.]+)\s*;"#
);
static_regex!(
    re_cs_namespace,
    r#"(?:^|\n)\s*namespace\s+([A-Za-z0-9_.]+)(?:\s*;|\s*\{)"#
);
static_regex!(
    re_cs_class,
    r#"(?:^|\n)\s*(?:\[[^\]]+\]\s*)*(?:(?:public|protected|private|internal|abstract|sealed|static|partial|readonly|ref)\s+)*(class|interface|struct|record(?:\s+struct|\s+class)?|enum)\s+([A-Za-z0-9_]+)(?:<[^>]*>)?(?:\s*:\s*([^{;]+))?\s*\{"#
);
static_regex!(
    re_cs_prop_or_field,
    r#"(?:^|\n)\s*(?:\[[^\]]+\]\s*)*(?:(?:public|protected|private|internal|static|readonly|volatile)\s+)+([A-Za-z0-9_<>\[\]?,\s]+?)\s+([A-Za-z0-9_]+)\s*(?:\{\s*(?:get|set|init)[^}]*\}|=[^;]+;|\;)"#
);
static_regex!(
    re_cs_method,
    r#"(?:^|\n)\s*(?:\[[^\]]+\]\s*)*(?:(?:public|protected|private|internal|static|virtual|override|abstract|sealed|async|partial|extern)\s+)*(?:([A-Za-z0-9_<>\[\]?,\s]+)\s+)?([A-Za-z0-9_]+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)\s*(?:where[^{]+)?\s*\{"#
);
static_regex!(
    re_cs_route_attr,
    r#"\[(HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)\s*(?:\(\s*["']([^"']+)["'])?"#
);
static_regex!(
    re_cs_minimal_api,
    r#"(?:app|endpoints|group)\.(MapGet|MapPost|MapPut|MapDelete|MapPatch)\s*\(\s*["']([^"']+)["']"#
);
static_regex!(
    re_cs_call,
    r#"(?:\.|\b)([a-zA-Z0-9_]+)\s*\("#
);

fn is_csharp_keyword(word: &str) -> bool {
    matches!(
        word,
        "abstract" | "as" | "base" | "bool" | "break" | "byte" | "case" | "catch" | "char"
            | "checked" | "class" | "const" | "continue" | "decimal" | "default" | "delegate"
            | "do" | "double" | "else" | "enum" | "event" | "explicit" | "extern" | "false"
            | "finally" | "fixed" | "float" | "for" | "foreach" | "goto" | "if" | "implicit"
            | "in" | "int" | "interface" | "internal" | "is" | "lock" | "long" | "namespace"
            | "new" | "null" | "object" | "operator" | "out" | "override" | "params"
            | "private" | "protected" | "public" | "readonly" | "ref" | "return" | "sbyte"
            | "sealed" | "short" | "sizeof" | "stackalloc" | "static" | "string" | "struct"
            | "switch" | "this" | "throw" | "true" | "try" | "typeof" | "uint" | "ulong"
            | "unchecked" | "unsafe" | "ushort" | "using" | "virtual" | "void" | "volatile"
            | "while" | "async" | "await" | "record" | "init" | "var" | "Console" | "Task"
    )
}

pub fn analyze_csharp(rel_path: &str, content: &str) -> FileAnalysis {
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
    file_bubble.docstring = format!("Fichier source C# {}", rel_path);
    file_bubble.lines_count = content.lines().count();
    file_bubble.complexity = compute_complexity(content);
    file_bubble.metadata.lines = file_bubble.lines_count;
    file_bubble.metadata.file_type = "csharp".to_string();
    nodes.push(file_bubble);

    // 1. Usings: using Foo; using static Foo; using Alias = Bar;
    for cap in re_cs_using().captures_iter(content) {
        if let Some(target_match) = cap.get(2) {
            let full_ns = target_match.as_str().trim();
            if !full_ns.is_empty() {
                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: full_ns.to_string(),
                    relation: "imports".to_string(),
                    order_label: format!("Using {}", full_ns),
                });
            }
        }
    }

    // 2. Namespaces: namespace Foo { or namespace Foo;
    for cap in re_cs_namespace().captures_iter(content) {
        if let Some(ns_match) = cap.get(1) {
            let ns_name = ns_match.as_str().trim();
            if !ns_name.is_empty() {
                let match_0 = cap.get(0).unwrap();
                let line_no = line_number_at(content, match_0.start());
                let ns_node_id = format!("namespace::{}::{}", rel_path, ns_name);
                let mut ns_bubble = SymbolBubble::new(
                    ns_node_id.clone(),
                    ns_name.to_string(),
                    rel_path.to_string(),
                    line_no,
                    SymbolKind::Contract,
                    galaxy.clone(),
                    detect_layer(rel_path, "namespace"),
                );
                ns_bubble.folder = folder.clone();
                ns_bubble.stereotype = "«Namespace»".to_string();
                nodes.push(ns_bubble);

                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: ns_node_id,
                    relation: "contains".to_string(),
                    order_label: format!("Namespace {}", ns_name),
                });
            }
        }
    }

    // 3. Types: class, interface, struct, record, record struct, record class, enum
    for cap in re_cs_class().captures_iter(content) {
        let type_kind = cap.get(1).map(|m| m.as_str()).unwrap_or("class");
        let name = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        if name.is_empty() || is_csharp_keyword(name) {
            continue;
        }

        let match_0 = cap.get(0).unwrap();
        let line_no = line_number_at(content, match_0.start());
        let node_id = format!("{}::{}", rel_path, name);
        let layer = detect_layer(rel_path, name);

        let mut bases = Vec::new();
        if let Some(bases_match) = cap.get(3) {
            for b in bases_match.as_str().split(',') {
                let clean_base = b.trim().split('<').next().unwrap_or("").trim();
                if !clean_base.is_empty() && !is_csharp_keyword(clean_base) {
                    bases.push(clean_base.to_string());
                    calls.push(RawCall {
                        caller: node_id.clone(),
                        callee: clean_base.to_string(),
                        relation: "inherits".to_string(),
                        order_label: format!("Hérite de {}", clean_base),
                    });
                }
            }
        }

        let mut stereo = if type_kind == "interface" {
            "«Interface»".to_string()
        } else if type_kind.starts_with("record") {
            "«Record»".to_string()
        } else if type_kind == "enum" {
            "«Enum»".to_string()
        } else if type_kind == "struct" {
            "«Struct»".to_string()
        } else {
            detect_stereotype(name, true, &layer, &bases)
        };

        if bases.iter().any(|b| b == "Controller" || b == "ControllerBase") || name.ends_with("Controller") {
            stereo = "«Controller»".to_string();
        }

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        // Extract properties and fields
        let after_slice = safe_slice(content, match_0.end(), 12000);
        let body_end = after_slice.rfind('}').unwrap_or(after_slice.len());
        let class_body = &after_slice[..body_end];

        let mut attributes = Vec::new();
        for p_cap in re_cs_prop_or_field().captures_iter(class_body) {
            let p_type = p_cap.get(1).map(|m| m.as_str().trim().to_string());
            let p_name = p_cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            if !p_name.is_empty() && !is_csharp_keyword(p_name) {
                attributes.push(AstAttribute {
                    name: p_name.to_string(),
                    r#type: p_type.clone(),
                });

                // Property bubble creation
                let p_match_0 = p_cap.get(0).unwrap();
                let prop_line = line_number_at(content, match_0.end() + p_match_0.start());
                let prop_id = format!("{}::{}::{}", rel_path, name, p_name);
                let mut prop_bubble = SymbolBubble::new(
                    prop_id.clone(),
                    p_name.to_string(),
                    rel_path.to_string(),
                    prop_line,
                    SymbolKind::Contract,
                    galaxy.clone(),
                    layer.clone(),
                );
                prop_bubble.folder = folder.clone();
                prop_bubble.stereotype = "«Property»".to_string();
                nodes.push(prop_bubble);

                calls.push(RawCall {
                    caller: node_id.clone(),
                    callee: prop_id,
                    relation: "contains".to_string(),
                    order_label: "Propriété".to_string(),
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
        class_bubble.metadata.attributes = attributes;
        class_bubble.docstring = extract_leading_doc(content, match_0.start(), false);
        nodes.push(class_bubble);
    }

    // 4. Methods, Endpoints & Route Attributes
    let mut seen_methods = HashSet::new();
    for cap in re_cs_method().captures_iter(content) {
        let ret_type = cap.get(1).map(|m| m.as_str().trim().to_string());
        let name = cap.get(2).map(|m| m.as_str().trim()).unwrap_or("");
        if name.is_empty() || is_csharp_keyword(name) {
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

        let route_cap = re_cs_route_attr()
            .captures(match_0.as_str())
            .or_else(|| re_cs_route_attr().captures(prefix_slice));

        let layer = detect_layer(rel_path, name);
        let is_endpoint = route_cap.is_some();
        let stereo = if is_endpoint {
            "«Endpoint»".to_string()
        } else {
            detect_stereotype(name, false, &layer, &[])
        };

        if let Some(rc) = route_cap {
            let verb = rc.get(1).map(|m| m.as_str()).unwrap_or("Route");
            let path_val = rc.get(2).map(|m| m.as_str()).unwrap_or("");
            routes_declared.push((format!("{}: {}", verb, path_val), node_id.clone()));
        }

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: node_id.clone(),
            relation: "contains".to_string(),
            order_label: "Contient".to_string(),
        });

        let body_slice = extract_fn_body_slice(content, match_0.end(), 4000);
        let mut method_calls = Vec::new();

        for c_cap in re_cs_call().captures_iter(body_slice) {
            let callee = c_cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            if !callee.is_empty()
                && callee != name
                && !is_csharp_keyword(callee)
                && callee != "Console"
                && callee != "WriteLine"
                && callee != "Write"
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
            is_async: Some(match_0.as_str().contains("async ")),
            calls: method_calls,
            docstring: if leading_doc.is_empty() { None } else { Some(leading_doc) },
        });

        nodes.push(fn_bubble);
    }

    // 5. Minimal APIs: app.MapGet("/path", ...);
    for m_cap in re_cs_minimal_api().captures_iter(content) {
        let verb = m_cap.get(1).map(|m| m.as_str()).unwrap_or("MapGet");
        let route_path = m_cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let match_0 = m_cap.get(0).unwrap();
        let line_no = line_number_at(content, match_0.start());
        let endpoint_name = format!("{}: {}", verb, route_path);
        let ep_id = format!("endpoint::{}::{}", rel_path, endpoint_name);

        routes_declared.push((endpoint_name.clone(), ep_id.clone()));

        let mut ep_bubble = SymbolBubble::new(
            ep_id.clone(),
            endpoint_name,
            rel_path.to_string(),
            line_no,
            SymbolKind::FormOrEndpoint,
            galaxy.clone(),
            "action".to_string(),
        );
        ep_bubble.folder = folder.clone();
        ep_bubble.stereotype = "«Endpoint»".to_string();
        nodes.push(ep_bubble);

        calls.push(RawCall {
            caller: file_node_id.clone(),
            callee: ep_id,
            relation: "contains".to_string(),
            order_label: "Endpoint".to_string(),
        });
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

pub fn analyze_csharp_symbols(file_path: &Path, content: &str) -> Vec<SymbolBubble> {
    analyze_csharp(&file_path.to_string_lossy().replace('\\', "/"), content).nodes
}
