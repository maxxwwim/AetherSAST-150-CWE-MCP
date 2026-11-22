use core_graph::bubble::{AstMethod, SymbolBubble, SymbolKind};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

use crate::scanner::{detect_galaxy, folder_from_rel_path, normalize_path, FileAnalysis, RawCall};

static_regex!(re_md_link, r#"\[([^\]]+)\]\(([^)]+)\)"#);
static_regex!(
    re_md_wiki,
    r#"\[\[([^\]|#]+)(?:#[^\]|]*)?(?:\|[^\]]+)?\]\]"#
);
static_regex!(re_md_code, r#"`([A-Za-z0-9_]{3,40})`"#);

pub(crate) fn analyze_markdown(rel_path: &str, content: &str) -> FileAnalysis {
    let mut nodes = Vec::new();
    let mut calls = Vec::new();

    let galaxy = detect_galaxy(rel_path);
    let file_node_id = format!("file::{}", rel_path);
    let folder = folder_from_rel_path(rel_path);

    let mut doc_title = String::new();
    let mut sections = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# ") {
            if doc_title.is_empty() {
                doc_title = trimmed.trim_start_matches("# ").trim().to_string();
            }
            sections.push(AstMethod {
                name: trimmed.to_string(),
                args: None,
                returns: None,
                is_async: None,
                calls: Vec::new(),
                docstring: None,
            });
        } else if trimmed.starts_with("## ") || trimmed.starts_with("### ") {
            sections.push(AstMethod {
                name: trimmed.to_string(),
                args: None,
                returns: None,
                is_async: None,
                calls: Vec::new(),
                docstring: None,
            });
        }
    }

    if doc_title.is_empty() {
        doc_title = Path::new(rel_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| rel_path.to_string());
    }

    let mut doc_bubble = SymbolBubble::new(
        file_node_id.clone(),
        doc_title,
        rel_path.to_string(),
        1,
        SymbolKind::File,
        galaxy,
        "docs".to_string(),
    );
    doc_bubble.folder = folder.clone();
    doc_bubble.stereotype = "«Document»".to_string();
    doc_bubble.symbol_type = "document".to_string();
    doc_bubble.docstring = format!("Documentation Markdown : {}", rel_path);
    doc_bubble.lines_count = content.lines().count();
    doc_bubble.complexity = (1 + sections.len() as u32 / 2).max(1);
    doc_bubble.metadata.lines = doc_bubble.lines_count;
    doc_bubble.metadata.file_type = "markdown".to_string();
    doc_bubble.metadata.methods = sections;
    // Keep raw_content for READMEs under 32 KB so doc impact zones & preview work immediately
    if content.len() <= 32_768 {
        doc_bubble.metadata.raw_content = Some(content.to_string());
    }
    nodes.push(doc_bubble);

    let cur_dir = Path::new(rel_path)
        .parent()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();

    // 1. Markdown links: [Text](path/to/file)
    for cap in re_md_link().captures_iter(content) {
        if let Some(target) = cap.get(2) {
            let t_str = target.as_str().trim();
            if !t_str.starts_with("http://")
                && !t_str.starts_with("https://")
                && !t_str.starts_with('#')
            {
                let clean_target = t_str.split('#').next().unwrap_or(t_str);
                let resolved = if clean_target.starts_with('/') {
                    clean_target.trim_start_matches('/').to_string()
                } else if !cur_dir.is_empty() {
                    format!("{}/{}", cur_dir, clean_target)
                } else {
                    clean_target.to_string()
                };
                let norm = normalize_path(&resolved);
                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: format!("file::{}", norm),
                    relation: "documents".to_string(),
                    order_label: "Documente".to_string(),
                });
            }
        }
    }

    // 2. Obsidian Wikilinks: [[Target]]
    for cap in re_md_wiki().captures_iter(content) {
        if let Some(target) = cap.get(1) {
            let t_name = target.as_str().trim();
            if !t_name.is_empty() {
                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: t_name.to_string(),
                    relation: "documents".to_string(),
                    order_label: "Documente".to_string(),
                });
            }
        }
    }

    // 3. Inline code backticks: `SymbolName`
    let ignore_words = [
        "true",
        "false",
        "null",
        "undefined",
        "const",
        "let",
        "var",
        "function",
        "string",
        "number",
        "boolean",
        "async",
        "await",
        "import",
        "export",
        "npm",
        "pnpm",
        "yarn",
        "bash",
        "json",
        "rust",
        "python",
        "test",
        "cargo",
        "self",
    ];
    for cap in re_md_code().captures_iter(content) {
        if let Some(word) = cap.get(1) {
            let w = word.as_str();
            if !ignore_words.contains(&w.to_lowercase().as_str()) {
                calls.push(RawCall {
                    caller: file_node_id.clone(),
                    callee: w.to_string(),
                    relation: "documents".to_string(),
                    order_label: "Documente".to_string(),
                });
            }
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
