//! Empirical adversarial stress-test suite for `obsidian-vault`.
//!
//! Validates:
//! 1. Adversarial Wikilinks & Transclusions (multiple pipes, multiple hashes, empty brackets, escapes)
//! 2. Code Block, Inline Code, Comment, and Math Block Masking
//! 3. Tag Boundaries & Hierarchies (numeric tags, unicode tags, headers, boundary punctuation)
//! 4. YAML Frontmatter Edge Cases (flow lists, block lists, unclosed fences, malformed syntax)
//! 5. Graph Integrity & Backlinks (circular links, self-links, ghost notes de-duplication, multi-link weights)
//! 6. Layout Robustness (zero panics, finite coordinates, dynamic layout)
//! 7. Project Detector & Confinement Under Adversarial Inputs

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

use obsidian_vault::{
    build_vault_graph, detect_project_type,
    detect_project_type_with_options, extract_frontmatter,
    parse_markdown, parse_wikilinks_and_transclusions, scan_obsidian_vault,
    DetectedProjectType, DetectorOptions, PathGuard,
};

// ============================================================================
// Group 1: Adversarial Markdown Parsing (Wikilinks, Transclusions, Code Blocks)
// ============================================================================

#[test]
fn test_adv_wikilinks_complex_pipes_and_hashes() {
    let input = r###"
[[Target|Alias|Extra|More]]
[[Target#Section#SubSection#Detail]]
[[Target#Heading|Alias|ExtraPipes]]
[[Target#^b123|BlockLabel|Extra]]
[[#OnlyHeading#Sub]]
[[#^onlyblock|Label]]
"###;
    let doc = parse_markdown(input, Path::new("adv_links.md"));
    assert_eq!(doc.wikilinks.len(), 6, "All 6 complex wikilinks must parse without panic");

    // 1. Multiple pipes
    let link0 = &doc.wikilinks[0];
    assert_eq!(link0.target, "Target");
    assert!(link0.label.is_some());
    // Label captures remainder after first pipe
    assert_eq!(link0.label.as_deref(), Some("Alias|Extra|More"));

    // 2. Multiple hashes
    let link1 = &doc.wikilinks[1];
    assert_eq!(link1.target, "Target");
    assert_eq!(link1.anchor.as_deref(), Some("Section#SubSection#Detail"));

    // 3. Hash + multiple pipes
    let link2 = &doc.wikilinks[2];
    assert_eq!(link2.target, "Target");
    assert_eq!(link2.anchor.as_deref(), Some("Heading"));
    assert_eq!(link2.label.as_deref(), Some("Alias|ExtraPipes"));

    // 4. Block ref + multiple pipes
    let link3 = &doc.wikilinks[3];
    assert_eq!(link3.target, "Target");
    assert!(link3.is_block_ref);
    assert_eq!(link3.block_id.as_deref(), Some("b123"));
    assert_eq!(link3.label.as_deref(), Some("BlockLabel|Extra"));

    // 5. Self-anchor with multiple hashes
    let link4 = &doc.wikilinks[4];
    assert_eq!(link4.target, "");
    assert_eq!(link4.anchor.as_deref(), Some("OnlyHeading#Sub"));

    // 6. Self-anchor block ref
    let link5 = &doc.wikilinks[5];
    assert_eq!(link5.target, "");
    assert!(link5.is_block_ref);
    assert_eq!(link5.block_id.as_deref(), Some("onlyblock"));
    assert_eq!(link5.label.as_deref(), Some("Label"));
}

#[test]
fn test_adv_wikilinks_empty_brackets_and_escapes() {
    let input = r###"
[[]]
[[ ]]
[[   ]]
[[#]]
[[# ]]
\[\[EscapedLink1\]\]
\[\[EscapedWithAlias|Alias\]\]
prefix\[\[EscapedLink2\]\]
[[ValidLink1]][[ValidLink2]]
[\[BrokenBracket1]]
[[BrokenBracket2\]]
"###;
    let doc = parse_markdown(input, Path::new("test_escapes.md"));

    let targets: Vec<&str> = doc.wikilinks.iter().map(|w| w.target.as_str()).collect();

    // Valid links extracted
    assert!(targets.contains(&"ValidLink1"), "ValidLink1 must be extracted");
    assert!(targets.contains(&"ValidLink2"), "ValidLink2 must be extracted");

    // Escaped links must NOT be extracted
    assert!(!targets.contains(&"EscapedLink1"), "Escaped link must be ignored");
    assert!(!targets.contains(&"EscapedWithAlias"), "Escaped link with alias must be ignored");
    assert!(!targets.contains(&"EscapedLink2"), "Prefix escaped link must be ignored");

    // Empty brackets must NOT produce empty targets
    for w in &doc.wikilinks {
        if w.target.is_empty() {
            assert!(w.anchor.is_some(), "Only self-anchors may have an empty target");
        }
    }
}

#[test]
fn test_adv_code_block_masking_deep() {
    let input = r###"
Before code block [[RealLinkBefore]] #real_tag_before

```rust
// Fenced with 3 backticks
let link = "[[CodeLink1]]";
let tag = "#tag_in_code_1";
/* HTML comment inside code: <!-- [[CommentInCode]] --> */
```

````markdown
Fenced with 4 backticks
```rust
let nested = "[[NestedCodeLink]]";
```
#tag_in_4backticks
````

~~~python
# Tilde fence
def foo():
    x = "[[TildeLink]]"
    y = "#tilde_tag"
~~~

`[[InlineLink1]]` and `#inline_tag_1`
`` `[[DoubleTickInline]]` ``

<!--
Multi-line HTML comment
[[CommentLink1]]
#comment_tag_1
-->

After code block [[RealLinkAfter]] #real_tag_after
"###;

    let doc = parse_markdown(input, Path::new("mask_deep.md"));

    let targets: Vec<&str> = doc.wikilinks.iter().map(|w| w.target.as_str()).collect();
    assert_eq!(
        targets,
        vec!["RealLinkBefore", "RealLinkAfter"],
        "Only links outside code blocks and comments should be extracted"
    );

    let tags: Vec<&str> = doc.tags.iter().map(|t| t.tag.as_str()).collect();
    assert_eq!(
        tags,
        vec!["real_tag_before", "real_tag_after"],
        "Only tags outside code blocks and comments should be extracted"
    );
}

#[test]
fn test_adv_unclosed_code_blocks_and_comments() {
    // Unclosed 3-backtick fence: must mask to end of file without panic
    let unclosed_code = "Header text [[ValidLink]]\n```rust\nlet x = \"[[FakeLink]]\";\n#faketag";
    let doc_code = parse_markdown(unclosed_code, Path::new("unclosed_code.md"));
    assert_eq!(doc_code.wikilinks.len(), 1);
    assert_eq!(doc_code.wikilinks[0].target, "ValidLink");
    assert_eq!(doc_code.tags.len(), 0);

    // Unclosed HTML comment: must mask to end of file without panic
    let unclosed_comment = "Intro [[ValidLink]]\n<!-- Start of unclosed comment\n[[CommentLink]]\n#commenttag";
    let doc_comment = parse_markdown(unclosed_comment, Path::new("unclosed_comment.md"));
    assert_eq!(doc_comment.wikilinks.len(), 1);
    assert_eq!(doc_comment.wikilinks[0].target, "ValidLink");
    assert_eq!(doc_comment.tags.len(), 0);
}

#[test]
fn test_adv_math_blocks_behavior() {
    // Empirical test for math blocks: LaTeX formulas often contain $ or $$
    let math_input = r###"
# Math Note
Here is inline math: $E = mc^2$
And display math:
$$
\int_0^\infty f(x) dx
[[MathWikilink]]
#mathtag
$$
Normal link [[NormalLink]]
"###;
    let doc = parse_markdown(math_input, Path::new("math.md"));

    // Verify zero panics when encountering LaTeX math syntax
    let targets: Vec<&str> = doc.wikilinks.iter().map(|w| w.target.as_str()).collect();
    assert!(targets.contains(&"NormalLink"));

    // CommonMark standard masking only masks code blocks and comments.
    // LaTeX math delimiters $$ are unmasked, meaning syntax inside $$ is parsed as regular text.
    let math_link_captured = targets.contains(&"MathWikilink");
    assert!(math_link_captured, "Obsidian MathJax $$ blocks are treated as body text under CommonMark");
}

#[test]
fn test_adv_transclusions_edge_cases() {
    let input = r###"
![[NoteEmbed]]
![[NoteEmbed#Section Anchor]]
![[NoteEmbed#^block123]]
![[assets/image.PNG]]
![[assets/photo.jpeg|600x400]]
![[clip.mp4]]
![[audio.OGG]]
![[drawing.svg]]
![[manual.PDF]]
!\[\[EscapedEmbed\]\]
"###;
    let (_, trans) = parse_wikilinks_and_transclusions(input, 0);

    assert_eq!(trans.len(), 9, "All 9 unescaped transclusions must parse");

    // Case insensitivity of media extensions
    assert!(trans[3].is_media, "PNG uppercase must be detected as media");
    assert!(trans[4].is_media, "jpeg lowercase must be detected as media");
    assert_eq!(trans[4].label_or_size.as_deref(), Some("600x400"));
    assert!(trans[5].is_media, "mp4 must be media");
    assert!(trans[6].is_media, "OGG must be media");
    assert!(trans[7].is_media, "svg must be media");
    assert!(trans[8].is_media, "PDF must be media");

    // Non-media note embed
    assert!(!trans[0].is_media);
    assert_eq!(trans[1].anchor.as_deref(), Some("Section Anchor"));
    assert_eq!(trans[2].block_id.as_deref(), Some("block123"));
}

// ============================================================================
// Group 2: Tag Boundary & Edge Cases
// ============================================================================

#[test]
fn test_adv_tags_boundary_and_numeric_rules() {
    let input = r###"
#normal_tag
#hierarchical/parent/child/grandchild
#project/2026/q3
#release-2.0
#développement
#café_crème
#日本語_タグ

# Title 1 Heading (Must NOT be a tag)
## Title 2 Heading (Must NOT be a tag)
### Title 3 Heading (Must NOT be a tag)

#123 (Pure numeric, MUST be ignored)
#999/888 (Pure numeric nested, MUST be ignored)
#1st_place (Leading number, MUST be ignored)

#tag-with-hyphens
#tag_with_underscores

Punctuation tests:
(#in_parens)
[#in_brackets]
{#in_braces}
"#in_double_quotes"
'#in_single_quotes'
<#in_angle_brackets>
#with_comma, next
#with_semicolon; next
#with_period. next

Invalid tag forms:
#tag//double_slash
#trailing_slash/
#
"###;

    let doc = parse_markdown(input, Path::new("tags_adv.md"));
    let extracted: Vec<&str> = doc.tags.iter().map(|t| t.tag.as_str()).collect();

    // Valid tags
    assert!(extracted.contains(&"normal_tag"));
    assert!(extracted.contains(&"hierarchical/parent/child/grandchild"));
    assert!(extracted.contains(&"project/2026/q3"));
    assert!(extracted.contains(&"développement"));
    assert!(extracted.contains(&"café_crème"));
    assert!(extracted.contains(&"日本語_タグ"));
    assert!(extracted.contains(&"tag-with-hyphens"));
    assert!(extracted.contains(&"tag_with_underscores"));
    assert!(extracted.contains(&"in_parens"));
    assert!(extracted.contains(&"in_brackets"));
    assert!(extracted.contains(&"in_braces"));
    assert!(extracted.contains(&"in_double_quotes"));
    assert!(extracted.contains(&"in_single_quotes"));
    assert!(extracted.contains(&"with_comma"));
    assert!(extracted.contains(&"with_semicolon"));

    // Rejected forms
    assert!(!extracted.contains(&"123"), "Pure numeric #123 must be rejected");
    assert!(!extracted.contains(&"999/888"), "Pure numeric #999/888 must be rejected");
    assert!(!extracted.contains(&"1st_place"), "Leading digit in tag must be rejected");
    assert!(!extracted.contains(&"Title"), "Markdown headings must not be tags");
    assert!(!extracted.contains(&"tag//double_slash"), "Double slash tag must be rejected");
}

#[test]
fn test_adv_commonmark_headings_extraction() {
    let input = r###"
# Document Title
Some introduction.

## Section 1: Overview
Details here.

### Subsection 1.1: Architecture
Deep details.

#### H4 Heading
##### H5 Heading
###### H6 Heading
####### H7 is not a valid CommonMark heading (7 hashes)

Not a heading:
#NoSpaceHeading (treated as inline tag)
"###;
    let doc = parse_markdown(input, Path::new("headings.md"));
    assert_eq!(doc.section_headings.len(), 6);
    assert_eq!(doc.section_headings[0], "Document Title");
    assert_eq!(doc.section_headings[1], "Section 1: Overview");
    assert_eq!(doc.section_headings[2], "Subsection 1.1: Architecture");
    assert_eq!(doc.section_headings[3], "H4 Heading");
    assert_eq!(doc.section_headings[4], "H5 Heading");
    assert_eq!(doc.section_headings[5], "H6 Heading");

    // Title fallback
    assert_eq!(doc.title, "Document Title");
}

// ============================================================================
// Group 3: YAML Frontmatter Edge Cases
// ============================================================================

#[test]
fn test_adv_yaml_frontmatter_edge_cases() {
    // 1. Flow lists with standard quotes and tags
    let flow_yaml = r###"---
title: Advanced Vault Note
tags: [tagA, "#tagB", dev/rust, 2026]
aliases: [Alias1, Alias2]
status: in-progress
score: 42
verified: true
links: "[[RelatedNote]]"
---
# Body
"###;
    let fm1 = extract_frontmatter(flow_yaml).expect("Flow YAML must parse");
    assert_eq!(fm1.title.as_deref(), Some("Advanced Vault Note"));
    assert!(fm1.tags.contains(&"tagA".to_string()));
    assert!(fm1.tags.contains(&"tagB".to_string()));
    assert!(fm1.tags.contains(&"dev/rust".to_string()));
    assert_eq!(fm1.aliases, vec!["Alias1", "Alias2"]);
    assert_eq!(fm1.custom_attributes.get("status").map(|s| s.as_str()), Some("in-progress"));
    assert_eq!(fm1.custom_attributes.get("score").map(|s| s.as_str()), Some("42"));
    assert_eq!(fm1.custom_attributes.get("verified").map(|s| s.as_str()), Some("true"));

    // Wikilink inside YAML
    assert_eq!(fm1.frontmatter_wikilinks.len(), 1);
    assert_eq!(fm1.frontmatter_wikilinks[0].target, "RelatedNote");

    // 2. Frontmatter closed by `...` (YAML standard)
    let dots_yaml = "---\ntitle: Dots Closed\ntags: [dots]\n...\n# Content\n";
    let fm2 = extract_frontmatter(dots_yaml).expect("Frontmatter closed by ... must parse");
    assert_eq!(fm2.title.as_deref(), Some("Dots Closed"));
    assert_eq!(fm2.tags, vec!["dots"]);

    // 3. Frontmatter with empty line inside fences
    let empty_line_fm = "---\n\n---\n# Content\n";
    let fm3 = extract_frontmatter(empty_line_fm).expect("Frontmatter with empty line must parse without panic");
    assert!(fm3.tags.is_empty());
    assert!(fm3.aliases.is_empty());

    // 4. Consecutive fences `---\n---\n`: regex safely returns None without panicking
    let consecutive_fences = "---\n---\n# Content\n";
    let fm_consec = extract_frontmatter(consecutive_fences);
    assert!(fm_consec.is_none(), "Consecutive fences without newline return None gracefully");

    // 5. Malformed YAML (tab indentation or syntax violation) -> graceful recovery
    let malformed_yaml = "---\ntitle: [unclosed list\nkey: @invalid_yaml_char\n---\n# Body\n";
    let fm4 = extract_frontmatter(malformed_yaml);
    assert!(fm4.is_some(), "Malformed YAML must not crash, returns fallback FrontmatterData");

    // 6. Unquoted `#` inside flow sequence (comment in standard YAML)
    // Handled gracefully without panicking
    let unquoted_flow = "---\ntitle: Unquoted Flow\ntags: [tagA, #tagB]\n---\n# Body\n";
    let fm5 = extract_frontmatter(unquoted_flow);
    assert!(fm5.is_some(), "Unquoted # in flow sequence must not crash");
}

// ============================================================================
// Group 4: Graph Integrity & Algorithmic Stress
// ============================================================================

#[test]
fn test_adv_graph_circular_links_and_self_links() {
    let mut docs = HashMap::new();

    // Triangle cycle: A -> B -> C -> A
    // Plus self links: A -> A
    // Plus multi links: A -> B twice
    let doc_a = parse_markdown(
        "# Note A\nLinks to [[Note B]], [[Note B]], [[Note A]], and [[#InternalAnchor]]",
        Path::new("Note A.md"),
    );
    let doc_b = parse_markdown("# Note B\nLinks to [[Note C]]", Path::new("Note B.md"));
    let doc_c = parse_markdown("# Note C\nLinks to [[Note A]]", Path::new("Note C.md"));

    docs.insert(PathBuf::from("Note A.md"), doc_a);
    docs.insert(PathBuf::from("Note B.md"), doc_b);
    docs.insert(PathBuf::from("Note C.md"), doc_c);

    let graph = build_vault_graph("CycleVault", Path::new("."), &docs, &[]);

    assert_eq!(graph.nodes.len(), 3, "Exactly 3 notes in cycle");

    let node_a = graph.nodes.iter().find(|n| n.name == "Note A").unwrap();
    let node_b = graph.nodes.iter().find(|n| n.name == "Note B").unwrap();
    let node_c = graph.nodes.iter().find(|n| n.name == "Note C").unwrap();

    // Check degree calculations
    // In-degree A: from C (1) + from A self-link (1) = 2
    assert_eq!(node_a.in_degree, 2, "A receives link from C and self-link");
    // In-degree B: from A (1 edge with multiplicity) = 1
    assert_eq!(node_b.in_degree, 1, "B receives link from A");
    // In-degree C: from B (1) = 1
    assert_eq!(node_c.in_degree, 1, "C receives link from B");

    // Edges de-duplication:
    // A -> B (1 edge with higher weight due to duplicate link)
    // A -> A (1 edge for self-link)
    // B -> C (1 edge)
    // C -> A (1 edge)
    assert_eq!(graph.edges.len(), 4, "Duplicate links between same pair must collapse into single edge");

    let edge_a_to_b = graph
        .edges
        .iter()
        .find(|e| e.source == node_a.id && e.target == node_b.id)
        .expect("A -> B edge must exist");
    assert!(
        edge_a_to_b.weight > 1.5,
        "Duplicate link must increase edge weight (got {})",
        edge_a_to_b.weight
    );

    // Verify Obsidian layout is valid (no NaN or Inf)
    for node in &graph.nodes {
        assert!(node.x.is_finite(), "Node x must be finite");
        assert!(node.y.is_finite(), "Node y must be finite");
        assert!(node.layouts.obsidian.is_some(), "Obsidian layout must be populated");
    }
}

#[test]
fn test_adv_ghost_notes_deduplication_and_degree() {
    let mut docs = HashMap::new();

    // 5 different notes all link to the SAME ghost note [[PhantomHub]]
    for i in 1..=5 {
        let content = format!("# Source Note {}\nSee [[PhantomHub]]", i);
        let path_str = format!("notes/Note_{}.md", i);
        docs.insert(
            PathBuf::from(&path_str),
            parse_markdown(&content, Path::new(&path_str)),
        );
    }

    let graph = build_vault_graph("GhostVault", Path::new("."), &docs, &[]);

    // 5 source notes + 1 ghost note = 6 nodes
    assert_eq!(graph.nodes.len(), 6, "Ghost note must be de-duplicated into exactly 1 bubble");

    let ghost = graph
        .nodes
        .iter()
        .find(|n| n.stereotype == "«GhostNote»")
        .expect("Ghost note bubble must exist");

    assert_eq!(ghost.name, "PhantomHub");
    assert_eq!(ghost.in_degree, 5, "Ghost note in-degree must be exactly 5");
    assert_eq!(ghost.out_degree, 0, "Ghost note out-degree must be 0");
    assert_eq!(ghost.radius, 8.0, "Ghost note maintains compact radius");
    assert_eq!(ghost.color_rgba, [0.45, 0.45, 0.50, 0.6], "Ghost note translucent color");
}

#[test]
fn test_adv_scale_stress_200_notes_and_clusters() {
    let mut docs = HashMap::new();
    const NUM_NOTES: usize = 200;

    // Generate 200 notes across 4 folders with interconnected links
    for i in 0..NUM_NOTES {
        let folder = match i % 4 {
            0 => "core",
            1 => "modules",
            2 => "guides",
            _ => "api",
        };
        let target1 = (i + 1) % NUM_NOTES;
        let target2 = (i + 7) % NUM_NOTES;
        let ghost_target = format!("Ghost_{}", i % 10);

        let content = format!(
            "---\ntitle: Note {}\ntags: [vault, scale/test]\n---\n# Note {}\nLink to [[Note {}]] and [[Note {}]] and [[{}]]",
            i, i, target1, target2, ghost_target
        );
        let rel_path = format!("{}/Note_{}.md", folder, i);
        docs.insert(
            PathBuf::from(&rel_path),
            parse_markdown(&content, Path::new(&rel_path)),
        );
    }

    let graph = build_vault_graph("ScaleVault", Path::new("."), &docs, &[]);

    // 200 notes + 10 distinct ghost notes = 210 nodes
    assert_eq!(graph.nodes.len(), 210);
    assert!(graph.edges.len() >= 400);

    // Confirm zero panics, layout integrity, and coordinate validity
    for node in &graph.nodes {
        assert!(node.x.is_finite());
        assert!(node.y.is_finite());
        assert!(node.radius >= 8.0 && node.radius <= 48.0);
    }
}

// ============================================================================
// Group 5: Detector & Confinement Resilience
// ============================================================================

#[test]
fn test_adv_detector_pruned_directories_and_bounds() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create ignored directories with hundreds of files
    for ignored in &["target", "node_modules", ".git", "build", "dist"] {
        let ign_dir = root.join(ignored);
        fs::create_dir_all(&ign_dir).unwrap();
        for i in 0..20 {
            fs::write(ign_dir.join(format!("junk_{}.rs", i)), "fn dummy() {}").unwrap();
            fs::write(ign_dir.join(format!("doc_{}.md", i)), "# Junk").unwrap();
        }
    }

    // Create 3 genuine Rust files
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn lib() {}").unwrap();
    fs::write(root.join("src/utils.rs"), "pub fn utils() {}").unwrap();

    // Create 1 plain README.md
    fs::write(root.join("README.md"), "# Standard Code Project\nNothing obsidian here.").unwrap();

    let report = detect_project_type(root).expect("Detection must succeed");
    assert_eq!(report.code_files_count, 3, "Must only count genuine non-ignored code files");
    assert_eq!(report.markdown_files_count, 1, "Must only count genuine non-ignored markdown files");
    assert_eq!(report.project_type, DetectedProjectType::PureCode);
}

#[test]
fn test_adv_detector_syntax_sampling_limit() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Create 25 markdown files, each with 2 obsidian wikilinks
    for i in 0..25 {
        let content = format!("# Note {}\nSee [[Link A]] and [[Link B]]", i);
        fs::write(root.join(format!("note_{:02}.md", i)), content).unwrap();
    }

    let options = DetectorOptions {
        max_syntax_sample_files: 5, // Strict limit: sample only 5 files
        ..Default::default()
    };

    let report = detect_project_type_with_options(root, &options).expect("Detection must succeed");
    assert_eq!(report.markdown_files_count, 25);
    // 5 files * 2 links each = 10 markers
    assert_eq!(
        report.obsidian_syntax_markers_count, 10,
        "Sampling must strictly respect max_syntax_sample_files limit"
    );
    assert_eq!(report.project_type, DetectedProjectType::PureObsidianVault);
}

#[test]
fn test_adv_confinement_traversal_attacks() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let guard = PathGuard::new(root).unwrap();

    // Adversarial traversal payloads
    let payloads = [
        "../outside.txt",
        "..\\outside.txt",
        "foo/../../escape.md",
        "nested/../../../root.key",
        "/etc/passwd",
        "\\Windows\\System32\\calc.exe",
        "C:\\boot.ini",
        "file:///etc/hosts",
        "http://evil.com/payload.md",
        "file\0nullbyte.md",
        "\\\\server\\share\\malware.exe",
        "//server/share/malware.exe",
    ];

    for payload in &payloads {
        let result = guard.read_to_string(Path::new(payload));
        assert!(
            result.is_err(),
            "PathGuard must block adversarial payload: '{}'",
            payload
        );
    }
}

#[test]
fn test_adv_scan_obsidian_vault_comprehensive_e2e() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::create_dir_all(root.join(".obsidian")).unwrap();
    fs::create_dir_all(root.join("docs")).unwrap();
    fs::create_dir_all(root.join("assets")).unwrap();

    // 1. Index note
    fs::write(
        root.join("Index.md"),
        "---\ntitle: Vault Home\ntags: [hub, root/main]\naliases: [HomeNote]\n---\n# Welcome\n[[docs/Arch|Architecture Guide]]\n![[assets/diagram.png|800x600]]\n[[MissingStub]]\n#tag_inline",
    ).unwrap();

    // 2. Arch note with backlinks to HomeNote alias and circular to Index
    fs::write(
        root.join("docs/Arch.md"),
        "---\ntitle: Architecture\ntags: [tech, dev/rust]\n---\n# Architecture\nBack to [[HomeNote]] and self [[#Architecture]].\n[[Index]]\n```rust\nlet x = \"[[FakeCodeLink]]\";\n```",
    ).unwrap();

    // 3. Guide note that also links to HomeNote
    fs::write(
        root.join("docs/Guide.md"),
        "# Guide\nRefer to [[HomeNote]].",
    ).unwrap();

    // 4. Fake attachment
    fs::write(root.join("assets/diagram.png"), b"FAKE_PNG_HEADER_AND_BYTES").unwrap();

    let graph = scan_obsidian_vault(root).expect("End-to-end scan must succeed");

    // Nodes: Index, Arch, Guide, diagram.png, MissingStub (ghost) = 5 nodes
    assert_eq!(graph.nodes.len(), 5, "Must contain exactly 5 nodes");

    let index_node = graph.nodes.iter().find(|n| n.name == "Vault Home").unwrap();
    let arch_node = graph.nodes.iter().find(|n| n.name == "Architecture").unwrap();
    let ghost_node = graph.nodes.iter().find(|n| n.stereotype == "«GhostNote»").unwrap();
    let att_node = graph.nodes.iter().find(|n| n.stereotype == "«Attachment»").unwrap();

    assert_eq!(ghost_node.name, "MissingStub");
    assert_eq!(att_node.name, "diagram.png");

    // In-degrees:
    // Index receives: Arch -> Index (merged direct and alias edge) (1) + Guide -> HomeNote (1) = 2
    assert_eq!(index_node.in_degree, 2, "Index has 2 incoming edges (from Arch and Guide)");
    // Arch receives: Index -> docs/Arch (1) + Arch self-link (1) = 2
    assert_eq!(arch_node.in_degree, 2, "Arch has 2 incoming links via Index and self-link");
    // Ghost receives: Index -> MissingStub (1) = 1
    assert_eq!(ghost_node.in_degree, 1);
    // Attachment receives: Index -> diagram.png embed (1) = 1
    assert_eq!(att_node.in_degree, 1);

    // Verify multi-link weight between Arch and Index:
    let arch_to_index_edge = graph
        .edges
        .iter()
        .find(|e| e.source.contains("Arch") && e.target.contains("Index"))
        .expect("Edge from Arch to Index must exist");
    assert!(
        arch_to_index_edge.weight >= 2.0,
        "Multiple links from Arch to Index must increment edge weight"
    );

    // Verify layout coordinates are synchronized and finite
    for node in &graph.nodes {
        assert!(node.x.is_finite());
        assert!(node.y.is_finite());
        assert!(node.layouts.obsidian.is_some());
    }
}
