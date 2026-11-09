//! Dedicated Obsidian vault parser, project classifier, and core-graph generator for AetherScope.
//!
//! Provides:
//! - Strict path confinement jail (`PathGuard`, `TargetJail`) preventing CWE-22 path traversals.
//! - Deterministic project classification (`detect_project_type`) into `PureObsidianVault`, `PureCode`, or `Mixed`.
//! - Obsidian Markdown AST parser (`parse_markdown`) extracting wikilinks, section anchors, block refs,
//!   transclusions, tags, and YAML frontmatter.
//! - Core-graph generation (`build_vault_graph`, `scan_obsidian_vault`) mapping notes into `SymbolBubble`
//!   and `AffiliationEdge` with `core_graph::layout::compute_obsidian_layout`.

pub mod confinement;
pub mod detector;
pub mod graph_builder;
pub mod parser;
pub mod types;

pub use confinement::{PathGuard, SecurityError, TargetJail};
pub use detector::{
    classify_project, count_markers_in_text, detect_project_type,
    detect_project_type_with_options, DetectorOptions,
};
pub use graph_builder::{
    build_vault_graph, create_attachment_bubble, create_ghost_note_bubble, create_note_bubble,
    VaultIndex,
};
pub use parser::{
    extract_frontmatter, extract_headings, mask_markdown_content, parse_inline_tags,
    parse_markdown, parse_wikilinks_and_transclusions,
};
pub use types::{
    BacklinkRecord, DetectedProjectType, FrontmatterData, ObsidianError, ParsedMarkdownDoc,
    ParsedNote, ProjectDetectionReport, TagOccurrence, TransclusionTarget, WikilinkTarget,
};

use core_graph::graph::AetherGraph;
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Scans an Obsidian vault rooted at `root`, enforcing strict path confinement,
/// parsing all markdown notes, resolving relations and backlinks, and generating
/// a production-grade `AetherGraph` with computed Obsidian layout.
pub fn scan_obsidian_vault(root: &Path) -> Result<AetherGraph, ObsidianError> {
    let guard = PathGuard::new(root)?;
    let canonical_root = guard.canonical_root();

    let vault_name = canonical_root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ObsidianVault")
        .to_string();

    let options = DetectorOptions::default();

    // 1. Discover Markdown files and Attachments
    let mut md_rel_paths = Vec::new();
    let mut attachment_rel_paths = Vec::new();

    for entry in WalkDir::new(canonical_root)
        .into_iter()
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            let file_name = e.file_name().to_string_lossy();
            if e.file_type().is_dir() {
                let name_lower = file_name.to_lowercase();
                if options
                    .ignored_directories
                    .iter()
                    .any(|d| d.to_lowercase() == name_lower)
                {
                    return false;
                }
                if file_name.starts_with('.') {
                    return false;
                }
            }
            true
        })
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let rel = match entry.path().strip_prefix(canonical_root) {
            Ok(p) => p.to_path_buf(),
            Err(_) => continue,
        };

        let ext = rel
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        if options.markdown_extensions.iter().any(|m| m == &ext) {
            md_rel_paths.push(rel);
        } else if TransclusionTarget::is_media_extension(&ext) {
            attachment_rel_paths.push(rel);
        }
    }

    // 2. Safely read and parse all Markdown files (leveraging Rayon parallelism)
    let parsed_results: Result<Vec<(PathBuf, ParsedNote)>, ObsidianError> = md_rel_paths
        .par_iter()
        .map(|rel| {
            let content = guard.read_to_string(rel)?;
            let parsed = parse_markdown(&content, rel);
            Ok((rel.clone(), parsed))
        })
        .collect();

    let parsed_list = parsed_results?;
    let mut parsed_docs = HashMap::with_capacity(parsed_list.len());
    for (rel, note) in parsed_list {
        parsed_docs.insert(rel, note);
    }

    // 3. Build graph
    let graph = build_vault_graph(
        &vault_name,
        canonical_root,
        &parsed_docs,
        &attachment_rel_paths,
    );

    Ok(graph)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, create_dir_all};
    use tempfile::tempdir;

    #[test]
    fn test_scan_obsidian_vault_end_to_end() {
        let dir = tempdir().unwrap();
        create_dir_all(dir.path().join(".obsidian")).unwrap();
        create_dir_all(dir.path().join("assets")).unwrap();

        fs::write(
            dir.path().join("Index.md"),
            "# Knowledge Base\nWelcome to [[Overview]] and ![[assets/logo.png|200]].\nTags: #kb/root",
        )
        .unwrap();

        fs::write(
            dir.path().join("Overview.md"),
            "---\ntags: [guide, arch]\naliases: [SystemOverview]\n---\n# Overview\nSee [[Index]] and [[DanglingTarget]].",
        )
        .unwrap();

        fs::write(dir.path().join("assets/logo.png"), b"PNG_FAKE_DATA").unwrap();

        let graph = scan_obsidian_vault(dir.path()).unwrap();

        assert_eq!(graph.project_name, dir.path().file_name().unwrap().to_str().unwrap());
        // Nodes: Index, Overview, logo.png, DanglingTarget (ghost) = 4
        assert_eq!(graph.nodes.len(), 4);

        let ghost = graph.nodes.iter().find(|n| n.stereotype == "«GhostNote»").unwrap();
        assert_eq!(ghost.name, "DanglingTarget");

        let att = graph.nodes.iter().find(|n| n.stereotype == "«Attachment»").unwrap();
        assert_eq!(att.name, "logo.png");

        assert_eq!(graph.edges.len(), 4); // Index->Overview, Index->logo.png, Overview->Index, Overview->DanglingTarget

        // Verify layout was computed
        for node in &graph.nodes {
            assert!(node.layouts.obsidian.is_some());
        }
    }
}
