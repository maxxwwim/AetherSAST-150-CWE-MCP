//! Graph builder generating `core-graph` primitives (`SymbolBubble`, `AffiliationEdge`,
//! `LayoutPositions` with Obsidian layout, and bidirectional backlinks) from parsed notes.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use core_graph::bubble::{
    AstAttribute, AstMethod, SymbolBubble, SymbolKind, SymbolMetadata,
};
use core_graph::edge::{AffiliationEdge, EdgeType, FilterAffiliation};
use core_graph::graph::{AetherGraph, GraphStats};
use core_graph::layout::compute_obsidian_layout;

use crate::types::ParsedNote;

/// Index of vault notes, aliases, and attachments enabling shortest-path link resolution.
#[derive(Default, Debug)]
pub struct VaultIndex {
    /// Canonical relative path (e.g. "docs/architecture.md") -> NoteId
    pub path_to_note_id: HashMap<String, String>,
    /// Lowercase stem (e.g. "architecture") -> list of note ids
    pub stem_to_note_ids: HashMap<String, Vec<String>>,
    /// Note title or frontmatter alias -> NoteId
    pub alias_to_note_id: HashMap<String, String>,
    /// Known attachments relative paths
    pub attachment_paths: HashSet<String>,
    /// Lowercase filename of attachment -> AttachmentId
    pub attachment_stem_to_id: HashMap<String, String>,
}

impl VaultIndex {
    /// Builds the resolution index from parsed notes and discovered attachments.
    pub fn build(
        docs: &HashMap<PathBuf, ParsedNote>,
        attachments: &[PathBuf],
        _vault_root: &Path,
    ) -> Self {
        let mut index = Self::default();

        // 1. Index Markdown Notes
        for (rel_path, doc) in docs {
            let rel_str = normalize_path(rel_path);
            let note_id = format!("note::{}", rel_str);

            index.path_to_note_id.insert(rel_str.clone(), note_id.clone());

            let stem = Path::new(&rel_str)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !stem.is_empty() {
                index.stem_to_note_ids.entry(stem.clone()).or_default().push(note_id.clone());
            }

            // Index note name directly
            index.alias_to_note_id.insert(stem, note_id.clone());

            // Index frontmatter aliases and title
            if let Some(ref fm) = doc.frontmatter {
                for alias in &fm.aliases {
                    index.alias_to_note_id.insert(alias.to_ascii_lowercase(), note_id.clone());
                }
                if let Some(ref title) = fm.title {
                    index.alias_to_note_id.insert(title.to_ascii_lowercase(), note_id.clone());
                }
            }
        }

        // 2. Index Attachments
        for att in attachments {
            let rel_str = normalize_path(att);
            let att_id = format!("attachment::{}", rel_str);
            index.attachment_paths.insert(rel_str.clone());

            let stem = Path::new(&rel_str)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !stem.is_empty() {
                index.attachment_stem_to_id.insert(stem, att_id);
            }
        }

        index
    }

    /// Resolves a wikilink target string to a NoteId, AttachmentId, or GhostNoteId.
    pub fn resolve_target(&self, source_rel_path: &str, raw_target: &str) -> String {
        let clean = raw_target
            .trim()
            .trim_start_matches('/')
            .trim_start_matches('\\')
            .trim_start_matches("./");

        // 1. Self anchor [[#heading]] -> target is empty, resolves to source note
        if clean.is_empty() {
            let source_clean = normalize_path(Path::new(source_rel_path));
            if let Some(id) = self.path_to_note_id.get(&source_clean) {
                return id.clone();
            }
            return format!("note::{}", source_clean);
        }

        let target_path = Path::new(clean);
        let target_stem = target_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(clean)
            .to_ascii_lowercase();

        // 2. Check exact relative path from vault root
        let as_md = if clean.ends_with(".md") {
            clean.to_string()
        } else {
            format!("{}.md", clean)
        };
        if let Some(id) = self.path_to_note_id.get(&as_md) {
            return id.clone();
        }

        // 3. Check relative to source note folder
        let source_folder = Path::new(source_rel_path).parent().unwrap_or(Path::new(""));
        let joined = source_folder.join(clean);
        let joined_str = normalize_path(&joined);
        let joined_md = if joined_str.ends_with(".md") {
            joined_str
        } else {
            format!("{}.md", joined_str)
        };
        if let Some(id) = self.path_to_note_id.get(&joined_md) {
            return id.clone();
        }

        // 4. Shortest path match: look up by stem
        if let Some(candidates) = self.stem_to_note_ids.get(&target_stem) {
            if candidates.len() == 1 {
                return candidates[0].clone();
            } else if candidates.len() > 1 {
                // Ambiguity resolution: pick candidate sharing closest folder distance
                return pick_closest_candidate(source_rel_path, candidates);
            }
        }

        // 5. Look up by alias or frontmatter title
        if let Some(id) = self.alias_to_note_id.get(&target_stem) {
            return id.clone();
        }

        // 6. Look up in attachment index
        let clean_filename = Path::new(clean)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if let Some(att_id) = self.attachment_stem_to_id.get(&clean_filename) {
            return att_id.clone();
        }

        // 7. Unresolved dangling link -> create Ghost Note
        format!("ghost::{}", clean.replace('\\', "/"))
    }
}

/// Creates a `SymbolBubble` for a real note.
pub fn create_note_bubble(rel_path: &str, doc: &ParsedNote) -> SymbolBubble {
    let clean_path = normalize_path(Path::new(rel_path));
    let id = format!("note::{}", clean_path);

    // Title preference: frontmatter title > doc.title > filename without .md
    let name = if !doc.title.is_empty() {
        doc.title.clone()
    } else {
        doc.name.clone()
    };

    let folder = if let Some(idx) = clean_path.rfind('/') {
        clean_path[..idx].to_string()
    } else {
        "root".to_string()
    };

    // Obsidian purple color
    let color_rgba = [0.55, 0.36, 0.96, 1.0];

    // Dynamic base radius proportional to sqrt of lines
    let radius = ((doc.lines_count as f32).sqrt() * 1.5 + 8.0).clamp(8.0, 32.0);

    let mut bubble = SymbolBubble::new(
        id,
        name,
        clean_path.clone(),
        1,
        SymbolKind::File,
        "vault".to_string(),
        "docs".to_string(),
    );

    bubble.folder = folder;
    bubble.stereotype = "«Note»".to_string();
    bubble.symbol_type = "note".to_string();
    bubble.color_rgba = color_rgba;
    bubble.radius = radius;
    bubble.lines_count = doc.lines_count;
    let total_links = doc.wikilinks.len().saturating_add(doc.tags.len());
    bubble.complexity = u32::try_from(total_links).unwrap_or(u32::MAX);
    bubble.is_dead_code = false;

    // Build metadata attributes for frontmatter
    let mut attributes = Vec::new();
    if let Some(ref fm) = doc.frontmatter {
        for (k, v) in &fm.custom_attributes {
            attributes.push(AstAttribute {
                name: k.clone(),
                r#type: Some(v.clone()),
            });
        }
        for tag in &fm.tags {
            attributes.push(AstAttribute {
                name: "tag".to_string(),
                r#type: Some(tag.clone()),
            });
        }
    }

    // Build section headings as AstMethod
    let mut methods = Vec::new();
    for heading in &doc.section_headings {
        methods.push(AstMethod {
            name: heading.clone(),
            args: None,
            returns: None,
            is_async: None,
            calls: Vec::new(),
            docstring: None,
        });
    }

    bubble.metadata = SymbolMetadata {
        lines: doc.lines_count,
        file_type: "markdown".to_string(),
        methods,
        attributes,
        raw_content: None,
        blake3_hash: None,
        file_blake3_hash: None,
        lock_verified: None,
        ears_count: 0,
        contract_folder: None,
        max_lines_limit: None,
        file_max_lines_override: None,
        violations: Vec::new(),
        cve_anomalies: Vec::new(),
    };

    bubble
}

/// Creates a placeholder `SymbolBubble` for an unresolved/ghost note.
pub fn create_ghost_note_bubble(ghost_id: &str) -> SymbolBubble {
    let name = ghost_id.strip_prefix("ghost::").unwrap_or(ghost_id).to_string();
    let file_path = format!("ghost/{}", name);

    let mut bubble = SymbolBubble::new(
        ghost_id.to_string(),
        name,
        file_path,
        0,
        SymbolKind::File,
        "vault".to_string(),
        "docs".to_string(),
    );

    bubble.folder = "ghosts".to_string();
    bubble.stereotype = "«GhostNote»".to_string();
    bubble.symbol_type = "ghost_note".to_string();
    // Translucent grey
    bubble.color_rgba = [0.45, 0.45, 0.50, 0.6];
    bubble.radius = 8.0;
    bubble.lines_count = 0;
    bubble.complexity = 0;
    bubble.is_dead_code = false;

    bubble
}

/// Creates a `SymbolBubble` for a media or binary attachment.
pub fn create_attachment_bubble(rel_path: &str) -> SymbolBubble {
    let clean_path = normalize_path(Path::new(rel_path));
    let id = format!("attachment::{}", clean_path);
    let name = Path::new(&clean_path)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(&clean_path)
        .to_string();

    let folder = if let Some(idx) = clean_path.rfind('/') {
        clean_path[..idx].to_string()
    } else {
        "assets".to_string()
    };

    let mut bubble = SymbolBubble::new(
        id,
        name,
        clean_path,
        1,
        SymbolKind::File,
        "vault".to_string(),
        "docs".to_string(),
    );

    bubble.folder = folder;
    bubble.stereotype = "«Attachment»".to_string();
    bubble.symbol_type = "attachment".to_string();
    // Cyan color
    bubble.color_rgba = [0.20, 0.70, 0.85, 1.0];
    bubble.radius = 10.0;
    bubble.lines_count = 1;
    bubble.complexity = 0;
    bubble.is_dead_code = false;

    bubble
}

/// Builds the complete `AetherGraph` from parsed notes and attachments.
pub fn build_vault_graph(
    vault_name: &str,
    vault_root: &Path,
    parsed_docs: &HashMap<PathBuf, ParsedNote>,
    attachments: &[PathBuf],
) -> AetherGraph {
    let index = VaultIndex::build(parsed_docs, attachments, vault_root);

    let mut nodes_map: HashMap<String, SymbolBubble> = HashMap::new();
    let mut edges_map: HashMap<(String, String, String), AffiliationEdge> = HashMap::new();
    let mut ghost_targets: HashSet<String> = HashSet::new();

    // 1. Generate Note Bubbles
    for (rel_path, doc) in parsed_docs {
        let rel_str = normalize_path(rel_path);
        let bubble = create_note_bubble(&rel_str, doc);
        nodes_map.insert(bubble.id.clone(), bubble);
    }

    // 2. Generate Attachment Bubbles
    for att in attachments {
        let rel_str = normalize_path(att);
        let bubble = create_attachment_bubble(&rel_str);
        nodes_map.insert(bubble.id.clone(), bubble);
    }

    // 3. Generate Edges (Wikilinks & Transclusions)
    for (rel_path, doc) in parsed_docs {
        let source_rel = normalize_path(rel_path);
        let source_id = format!("note::{}", source_rel);

        // A. Wikilinks -> EdgeType::Documents (relation: "links_to")
        for link in &doc.wikilinks {
            let target_id = index.resolve_target(&source_rel, &link.target);
            if target_id.starts_with("ghost::") {
                ghost_targets.insert(target_id.clone());
            }

            let key = (source_id.clone(), target_id.clone(), "links_to".to_string());
            let entry = edges_map.entry(key).or_insert_with(|| {
                let mut edge = AffiliationEdge::new(
                    source_id.clone(),
                    target_id.clone(),
                    EdgeType::Documents,
                    FilterAffiliation::SEMANTIC | FilterAffiliation::PHYSICAL,
                );
                edge.relation = "links_to".to_string();
                edge.label = link.label.clone();
                edge.order_label = link.anchor.clone().unwrap_or_default();
                edge.weight = 1.0;
                edge
            });
            entry.weight += 0.5; // Multiplicity increment
        }

        // B. Transclusions -> EdgeType::Render (relation: "embeds")
        for trans in &doc.transclusions {
            let target_id = index.resolve_target(&source_rel, &trans.target);
            if target_id.starts_with("ghost::") {
                ghost_targets.insert(target_id.clone());
            }

            let key = (source_id.clone(), target_id.clone(), "embeds".to_string());
            let entry = edges_map.entry(key).or_insert_with(|| {
                let mut edge = AffiliationEdge::new(
                    source_id.clone(),
                    target_id.clone(),
                    EdgeType::Render,
                    FilterAffiliation::PHYSICAL,
                );
                edge.relation = "embeds".to_string();
                edge.label = trans.label_or_size.clone();
                edge.order_label = trans.anchor.clone().unwrap_or_default();
                edge.weight = 1.5;
                edge
            });
            entry.weight += 0.5;
        }
    }

    // 4. Generate Ghost Note Bubbles
    for ghost_id in ghost_targets {
        nodes_map.entry(ghost_id.clone()).or_insert_with(|| create_ghost_note_bubble(&ghost_id));
    }

    // 5. Compute Bidirectional Backlinks & Degree Index
    let mut in_degrees: HashMap<String, usize> = HashMap::new();
    let mut out_degrees: HashMap<String, usize> = HashMap::new();

    for edge in edges_map.values() {
        *out_degrees.entry(edge.source.clone()).or_insert(0) += 1;
        *in_degrees.entry(edge.target.clone()).or_insert(0) += 1;
    }

    for (id, node) in nodes_map.iter_mut() {
        let in_deg = in_degrees.get(id).copied().unwrap_or(0);
        let out_deg = out_degrees.get(id).copied().unwrap_or(0);
        node.in_degree = in_deg;
        node.out_degree = out_deg;

        // Visual Hub Prominence: Boost radius based on in-degree (central knowledge hubs)
        if node.stereotype == "«Note»" {
            node.radius = (node.radius + (in_deg as f32).sqrt() * 2.0).clamp(8.0, 48.0);
        }
    }

    let mut nodes: Vec<SymbolBubble> = nodes_map.into_values().collect();
    let edges: Vec<AffiliationEdge> = edges_map.into_values().collect();

    // 6. Compute Obsidian Galaxy Layout
    compute_obsidian_layout(&mut nodes);

    // Synchronize x, y to layouts.obsidian
    for n in nodes.iter_mut() {
        if let Some(obs) = n.layouts.obsidian {
            n.x = obs.x;
            n.y = obs.y;
        }
    }

    // 7. Graph Statistics
    let total_nodes = nodes.len();
    let total_edges = edges.len();
    let files_scanned = nodes.iter().filter(|n| n.is_file).count();

    let stats = GraphStats {
        total_nodes,
        total_edges,
        files_scanned,
        dead_code_count: 0,
        ..Default::default()
    };

    AetherGraph {
        project_name: vault_name.to_string(),
        project_path: Some(vault_root.to_string_lossy().to_string()),
        generated_at: chrono::Utc::now().to_rfc3339(),
        system_prompt: Some("Obsidian Vault Knowledge Graph".to_string()),
        nodes,
        edges,
        stats,
        dataflow_graph: None,
    }
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string()
}

fn pick_closest_candidate(source_rel: &str, candidates: &[String]) -> String {
    let source_folder = Path::new(source_rel)
        .parent()
        .unwrap_or(Path::new(""))
        .to_string_lossy()
        .replace('\\', "/");
    let mut best_score = usize::MAX;
    let mut best_id = candidates[0].clone();

    for cand_id in candidates {
        let cand_path = cand_id.strip_prefix("note::").unwrap_or(cand_id);
        let cand_folder = Path::new(cand_path)
            .parent()
            .unwrap_or(Path::new(""))
            .to_string_lossy()
            .replace('\\', "/");

        let dist = folder_distance(&source_folder, &cand_folder);
        if dist < best_score {
            best_score = dist;
            best_id = cand_id.clone();
        }
    }

    best_id
}

fn folder_distance(a: &str, b: &str) -> usize {
    let parts_a: Vec<&str> = a.split('/').filter(|s| !s.is_empty()).collect();
    let parts_b: Vec<&str> = b.split('/').filter(|s| !s.is_empty()).collect();
    let mut common = 0;
    while common < parts_a.len() && common < parts_b.len() && parts_a[common] == parts_b[common] {
        common += 1;
    }
    (parts_a.len() - common) + (parts_b.len() - common)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_markdown;
    use std::path::PathBuf;

    #[test]
    fn test_note_and_ghost_bubble_mapping() {
        let mut docs = HashMap::new();

        // Note A links to Note B (exists) and Note C (missing -> ghost)
        let doc_a = parse_markdown("Link to [[Note B]] and [[Note C]]", Path::new("Note A.md"));
        let doc_b = parse_markdown("Content of B", Path::new("Note B.md"));

        docs.insert(PathBuf::from("Note A.md"), doc_a);
        docs.insert(PathBuf::from("Note B.md"), doc_b);

        let graph = build_vault_graph("MyVault", Path::new("."), &docs, &[]);

        // Node count: Note A, Note B, Ghost Note C = 3 nodes
        assert_eq!(graph.nodes.len(), 3);

        let node_a = graph.nodes.iter().find(|n| n.name == "Note A").unwrap();
        assert_eq!(node_a.kind, SymbolKind::File);
        assert_eq!(node_a.stereotype, "«Note»");
        assert_eq!(node_a.galaxy, "vault");
        assert_eq!(node_a.layer, "docs");
        assert_eq!(node_a.color_rgba, [0.55, 0.36, 0.96, 1.0]);
        assert_eq!(node_a.out_degree, 2);
        assert_eq!(node_a.in_degree, 0);

        let node_b = graph.nodes.iter().find(|n| n.name == "Note B").unwrap();
        assert_eq!(node_b.in_degree, 1);
        assert_eq!(node_b.out_degree, 0);

        let node_c = graph.nodes.iter().find(|n| n.name == "Note C").unwrap();
        assert_eq!(node_c.stereotype, "«GhostNote»");
        assert_eq!(node_c.color_rgba, [0.45, 0.45, 0.50, 0.6]);
        assert_eq!(node_c.in_degree, 1);

        // Edges: 2 links
        assert_eq!(graph.edges.len(), 2);
        for e in &graph.edges {
            assert_eq!(e.edge_type, EdgeType::Documents);
            assert_eq!(e.relation, "links_to");
        }
    }

    #[test]
    fn test_transclusion_attachment_and_embeds() {
        let mut docs = HashMap::new();
        let doc_a = parse_markdown("Here is diagram: ![[diagram.png]]", Path::new("Note A.md"));
        docs.insert(PathBuf::from("Note A.md"), doc_a);

        let attachments = vec![PathBuf::from("assets/diagram.png")];
        let graph = build_vault_graph("MyVault", Path::new("."), &docs, &attachments);

        let att_node = graph
            .nodes
            .iter()
            .find(|n| n.stereotype == "«Attachment»")
            .unwrap();
        assert_eq!(att_node.name, "diagram.png");
        assert_eq!(att_node.color_rgba, [0.20, 0.70, 0.85, 1.0]);

        let edge = graph
            .edges
            .iter()
            .find(|e| e.relation == "embeds")
            .unwrap();
        assert_eq!(edge.edge_type, EdgeType::Render);
        assert_eq!(edge.target, att_node.id);
    }

    #[test]
    fn test_backlink_degrees_and_self_links() {
        let mut docs = HashMap::new();
        // Note A links to itself via section anchor [[#Intro]]
        let doc_a = parse_markdown("# Intro\nSelf link [[#Intro]]", Path::new("Note A.md"));
        docs.insert(PathBuf::from("Note A.md"), doc_a);

        let graph = build_vault_graph("MyVault", Path::new("."), &docs, &[]);
        let node_a = graph.nodes.iter().find(|n| n.name == "Intro").unwrap();

        assert_eq!(node_a.in_degree, 1, "Self link increments in_degree");
        assert_eq!(node_a.out_degree, 1, "Self link increments out_degree");
    }

    #[test]
    fn test_alias_resolution() {
        let mut docs = HashMap::new();
        let doc_b = parse_markdown(
            "---\naliases: [QuickRef]\n---\n# Note B",
            Path::new("docs/Note B.md"),
        );
        let doc_a = parse_markdown("See [[QuickRef]]", Path::new("Note A.md"));

        docs.insert(PathBuf::from("Note A.md"), doc_a);
        docs.insert(PathBuf::from("docs/Note B.md"), doc_b);

        let graph = build_vault_graph("MyVault", Path::new("."), &docs, &[]);
        let edge = graph
            .edges
            .iter()
            .find(|e| e.source.contains("Note A"))
            .unwrap();
        assert!(
            edge.target.contains("Note B"),
            "Link to [[QuickRef]] should resolve to Note B via alias"
        );
    }

    #[test]
    fn test_obsidian_layout_computation() {
        let mut docs = HashMap::new();
        docs.insert(
            PathBuf::from("core/A.md"),
            parse_markdown("Link [[B]]", Path::new("core/A.md")),
        );
        docs.insert(
            PathBuf::from("core/B.md"),
            parse_markdown("Content", Path::new("core/B.md")),
        );
        docs.insert(
            PathBuf::from("guides/C.md"),
            parse_markdown("Link [[A]]", Path::new("guides/C.md")),
        );

        let graph = build_vault_graph("MyVault", Path::new("."), &docs, &[]);
        for node in &graph.nodes {
            assert!(
                node.layouts.obsidian.is_some(),
                "Every node must have obsidian layout coordinates"
            );
            let obs = node.layouts.obsidian.unwrap();
            assert_eq!(node.x, obs.x);
            assert_eq!(node.y, obs.y);
        }
    }
}
