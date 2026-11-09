//! Automatic project detection and classification engine.
//! Evaluates filesystem markers (.obsidian/), pruned file counts (code vs markdown),
//! and bounded markdown syntax sampling to classify targets into PureObsidianVault,
//! PureCode, or Mixed.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::types::{DetectedProjectType, ObsidianError, ProjectDetectionReport};

/// Configurable parameters for project detection.
#[derive(Debug, Clone)]
pub struct DetectorOptions {
    /// Maximum markdown files to sample for Obsidian syntax markers (default: 10).
    pub max_syntax_sample_files: usize,
    /// Maximum bytes to read per sampled markdown file (default: 64KB = 65,536).
    pub max_sample_bytes_per_file: usize,
    /// Directory names to prune during file traversal.
    pub ignored_directories: Vec<String>,
    /// File extensions classified as source code.
    pub code_extensions: Vec<String>,
    /// File extensions classified as Markdown documentation.
    pub markdown_extensions: Vec<String>,
}

impl Default for DetectorOptions {
    fn default() -> Self {
        Self {
            max_syntax_sample_files: 10,
            max_sample_bytes_per_file: 65_536,
            ignored_directories: vec![
                "target".to_string(),
                "node_modules".to_string(),
                ".git".to_string(),
                ".obsidian".to_string(),
                "bin".to_string(),
                "obj".to_string(),
                "dist".to_string(),
                "build".to_string(),
                ".turbo".to_string(),
                ".next".to_string(),
                "vendor".to_string(),
                ".cargo".to_string(),
                ".idea".to_string(),
                ".vscode".to_string(),
                ".venv".to_string(),
                "venv".to_string(),
            ],
            code_extensions: vec![
                "rs".to_string(), "zig".to_string(), "cs".to_string(),
                "ts".to_string(), "tsx".to_string(), "js".to_string(), "jsx".to_string(),
                "mjs".to_string(), "cjs".to_string(), "py".to_string(),
                "c".to_string(), "cpp".to_string(), "cc".to_string(), "cxx".to_string(),
                "h".to_string(), "hpp".to_string(), "hh".to_string(), "hxx".to_string(),
                "go".to_string(), "java".to_string(), "sol".to_string(), "yul".to_string(),
                "php".to_string(), "rb".to_string(), "swift".to_string(), "kt".to_string(),
                "scala".to_string(), "lua".to_string(),
            ],
            markdown_extensions: vec![
                "md".to_string(),
                "markdown".to_string(),
            ],
        }
    }
}

/// Detects the project classification and returns a comprehensive detection report.
///
/// Executes a 4-stage detection pipeline:
/// 1. Trigger 1: `.obsidian/` folder detection at root and depth <= 2.
/// 2. Trigger 2: High-speed pruned counting of source code files vs markdown files.
/// 3. Trigger 3: Bounded sampling of up to 10 markdown files for Obsidian syntax density.
/// 4. Trigger 4: Deterministic classification into PureObsidianVault, PureCode, or Mixed.
pub fn detect_project_type(root: &Path) -> Result<ProjectDetectionReport, ObsidianError> {
    detect_project_type_with_options(root, &DetectorOptions::default())
}

/// Detects the project classification with custom configuration options.
pub fn detect_project_type_with_options(
    root: &Path,
    options: &DetectorOptions,
) -> Result<ProjectDetectionReport, ObsidianError> {
    if !root.exists() {
        return Err(ObsidianError::InvalidRoot(format!(
            "Target directory does not exist: {}",
            root.display()
        )));
    }
    if !root.is_dir() {
        return Err(ObsidianError::InvalidRoot(format!(
            "Target path is not a directory: {}",
            root.display()
        )));
    }

    // ---------------------------------------------------------
    // Trigger 1: Search for `.obsidian/` at root and depth <= 2
    // ---------------------------------------------------------
    let (has_obsidian_dir, obsidian_dir_path) = find_obsidian_dir(root, options);

    // ---------------------------------------------------------
    // Trigger 2: Count Code Files vs Markdown Files (Pruned Walk)
    // ---------------------------------------------------------
    let mut code_files_count = 0usize;
    let mut markdown_files_count = 0usize;
    let mut sampled_md_paths = Vec::with_capacity(options.max_syntax_sample_files);

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            let file_name = e.file_name().to_string_lossy();
            // Prune ignored directories and hidden dot-directories
            if e.file_type().is_dir() {
                let name_lower = file_name.to_lowercase();
                if options.ignored_directories.iter().any(|d| d.to_lowercase() == name_lower) {
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

        let file_name = entry.file_name().to_string_lossy();
        let file_name_lower = file_name.to_lowercase();

        // Skip generated / minified / type declaration files
        if file_name_lower.ends_with(".min.js")
            || file_name_lower.ends_with(".bundle.js")
            || file_name_lower.ends_with(".d.ts")
            || file_name_lower == "build.rs"
        {
            continue;
        }

        let ext = entry
            .path()
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        if options.code_extensions.iter().any(|c| c == &ext) {
            code_files_count += 1;
        } else if options.markdown_extensions.iter().any(|m| m == &ext) {
            markdown_files_count += 1;
            if sampled_md_paths.len() < options.max_syntax_sample_files {
                sampled_md_paths.push(entry.path().to_path_buf());
            }
        }
    }

    // ---------------------------------------------------------
    // Trigger 3: Bounded Syntax Sampling of Markdown Files
    // ---------------------------------------------------------
    let obsidian_syntax_markers_count = sample_syntax_markers(&sampled_md_paths, options);

    // ---------------------------------------------------------
    // Trigger 4: Deterministic Classification Logic
    // ---------------------------------------------------------
    let project_type = classify_project(
        has_obsidian_dir,
        code_files_count,
        markdown_files_count,
        obsidian_syntax_markers_count,
    );

    let report = ProjectDetectionReport::new(
        project_type,
        has_obsidian_dir,
        obsidian_dir_path,
        code_files_count,
        markdown_files_count,
        obsidian_syntax_markers_count,
    );

    Ok(report)
}

/// Searches for the `.obsidian/` directory at root or documentation subdirectories (depth <= 2).
fn find_obsidian_dir(root: &Path, _options: &DetectorOptions) -> (bool, Option<String>) {
    // 1. Direct root check: root/.obsidian
    let root_dot = root.join(".obsidian");
    if root_dot.is_dir() {
        return (true, Some(".obsidian".to_string()));
    }

    // 2. Direct checks for prioritized documentation subdirectories
    let doc_folders = [
        "docs", "notes", "vault", "doc", "wiki", "documentation", "kb", "knowledge",
    ];
    for folder in &doc_folders {
        let candidate = root.join(folder).join(".obsidian");
        if candidate.is_dir() {
            let rel = format!("{}/.obsidian", folder);
            return (true, Some(rel));
        }
    }

    // 3. Fallback bounded walk up to depth 2 for any nested .obsidian directory
    for entry in WalkDir::new(root)
        .min_depth(1)
        .max_depth(2)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            let name_lower = name.to_lowercase();
            !matches!(
                name_lower.as_str(),
                "target" | "node_modules" | ".git" | "bin" | "obj" | "dist" | "build"
            )
        })
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_dir() && entry.file_name() == ".obsidian" {
            if let Ok(rel) = entry.path().strip_prefix(root) {
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                return (true, Some(rel_str));
            }
        }
    }

    (false, None)
}

/// Samples up to `max_syntax_sample_files` markdown files and counts Obsidian syntax markers.
fn sample_syntax_markers(sampled_paths: &[PathBuf], options: &DetectorOptions) -> usize {
    let mut total_markers = 0usize;

    for path in sampled_paths {
        if let Ok(mut file) = File::open(path) {
            let mut buffer = Vec::with_capacity(options.max_sample_bytes_per_file);
            let mut handle = (&mut file).take(options.max_sample_bytes_per_file as u64);
            if handle.read_to_end(&mut buffer).is_ok() {
                let content = String::from_utf8_lossy(&buffer);
                total_markers += count_markers_in_text(&content);
            }
        }
    }

    total_markers
}

/// Counts Obsidian syntax markers in a text snippet:
/// - Wikilinks `[[...]]`
/// - Transclusions `![[...] ]`
/// - Nested tags `#tag/subtag`
/// - Frontmatter tags/aliases
pub fn count_markers_in_text(text: &str) -> usize {
    let mut count = 0;

    // 1. Wikilinks & Transclusions: scan for `[[`
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i + 1 < len {
        if bytes[i] == b'[' && bytes[i + 1] == b'[' {
            // Find closing ]]
            let start = i + 2;
            if let Some(end_offset) = text[start..].find("]]") {
                let inside = &text[start..start + end_offset];
                if !inside.contains('\n') && !inside.trim().is_empty() {
                    count += 1;
                }
                i = start + end_offset + 2;
                continue;
            }
        }
        i += 1;
    }

    // 2. Hierarchical / nested tags: `#tag/subtag`
    for line in text.lines() {
        let trimmed = line.trim_start();
        // Skip markdown headings `# Heading`
        if trimmed.starts_with("# ") || trimmed.starts_with("## ") || trimmed.starts_with("### ") {
            continue;
        }

        let words = line.split_whitespace();
        for word in words {
            if word.starts_with('#') && word.len() > 2 {
                let tag_candidate = &word[1..];
                // Nested tag check: must contain at least one slash and alphanumeric segments
                if tag_candidate.contains('/') {
                    let segments: Vec<&str> = tag_candidate.split('/').collect();
                    let valid_segments = segments.iter().all(|seg| {
                        !seg.is_empty() && seg.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                    });
                    if valid_segments {
                        count += 1;
                    }
                }
            }
        }
    }

    // 3. YAML Frontmatter markers: check starting `---`
    if let Some(rest) = text.strip_prefix("---\n").or_else(|| text.strip_prefix("---\r\n")) {
        if let Some(end_idx) = rest.find("\n---").or_else(|| rest.find("\r\n---")) {
            let frontmatter = &rest[..end_idx];
            for fm_line in frontmatter.lines() {
                let trimmed = fm_line.trim();
                if trimmed.starts_with("tags:")
                    || trimmed.starts_with("tag:")
                    || trimmed.starts_with("aliases:")
                    || trimmed.starts_with("alias:")
                {
                    count += 1;
                }
            }
        }
    }

    count
}

/// Deterministic classification logic conforming to the specification decision matrix.
pub fn classify_project(
    has_obsidian_dir: bool,
    code_files_count: usize,
    markdown_files_count: usize,
    obsidian_syntax_markers_count: usize,
) -> DetectedProjectType {
    if has_obsidian_dir {
        if code_files_count == 0 {
            DetectedProjectType::PureObsidianVault
        } else if code_files_count <= 1 && markdown_files_count >= 10 {
            // Lone utility or export script in a note vault does not negate PureObsidianVault
            DetectedProjectType::PureObsidianVault
        } else {
            // Significant source code presence alongside .obsidian/
            DetectedProjectType::Mixed
        }
    } else if obsidian_syntax_markers_count > 0 {
        if code_files_count == 0 {
            DetectedProjectType::PureObsidianVault
        } else if markdown_files_count >= 1 {
            DetectedProjectType::Mixed
        } else {
            DetectedProjectType::PureCode
        }
    } else {
        // Neither .obsidian/ nor Obsidian syntax markers detected
        if code_files_count > 0 {
            DetectedProjectType::PureCode
        } else if markdown_files_count >= 3 {
            // Multiple markdown files without code treated as documentation vault
            DetectedProjectType::PureObsidianVault
        } else {
            // Default fallback for empty repos or single README
            DetectedProjectType::PureCode
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, create_dir_all};
    use tempfile::tempdir;

    #[test]
    fn test_case_01_pure_obsidian_vault_root_dot_obsidian() {
        let dir = tempdir().unwrap();
        create_dir_all(dir.path().join(".obsidian")).unwrap();
        fs::write(dir.path().join("NoteA.md"), "# Note A\n[[NoteB]]").unwrap();
        fs::write(dir.path().join("NoteB.md"), "# Note B\nSome text").unwrap();

        let report = detect_project_type(dir.path()).unwrap();
        assert_eq!(report.project_type, DetectedProjectType::PureObsidianVault);
        assert!(report.has_obsidian_dir);
        assert_eq!(report.obsidian_dir_path.as_deref(), Some(".obsidian"));
        assert_eq!(report.code_files_count, 0);
        assert_eq!(report.markdown_files_count, 2);
        assert!(report.obsidian_syntax_markers_count >= 1);
        assert_eq!(report.default_view, "vault");
        assert!(report.supported_views.contains(&"vault".to_string()));
        assert!(report.supported_views.contains(&"code".to_string()));
    }

    #[test]
    fn test_case_02_pure_obsidian_vault_with_single_utility_script() {
        let dir = tempdir().unwrap();
        create_dir_all(dir.path().join(".obsidian")).unwrap();
        create_dir_all(dir.path().join("scripts")).unwrap();
        fs::write(dir.path().join("scripts/export.py"), "print('export')").unwrap();
        for i in 0..12 {
            fs::write(
                dir.path().join(format!("Note_{}.md", i)),
                format!("# Note {}\n[[Index]]", i),
            ).unwrap();
        }

        let report = detect_project_type(dir.path()).unwrap();
        assert_eq!(report.project_type, DetectedProjectType::PureObsidianVault);
        assert_eq!(report.code_files_count, 1);
        assert_eq!(report.markdown_files_count, 12);
        assert_eq!(report.default_view, "vault");
    }

    #[test]
    fn test_case_03_mixed_project_with_docs_dot_obsidian() {
        let dir = tempdir().unwrap();
        create_dir_all(dir.path().join("docs/.obsidian")).unwrap();
        create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join("src/lib.rs"), "pub fn run() {}").unwrap();
        fs::write(dir.path().join("docs/Architecture.md"), "# Architecture\n[[Design]]").unwrap();

        let report = detect_project_type(dir.path()).unwrap();
        assert_eq!(report.project_type, DetectedProjectType::Mixed);
        assert!(report.has_obsidian_dir);
        assert_eq!(report.obsidian_dir_path.as_deref(), Some("docs/.obsidian"));
        assert_eq!(report.code_files_count, 2);
        assert_eq!(report.markdown_files_count, 1);
        assert_eq!(report.default_view, "code");
        assert!(report.allows_dual_vision());
    }

    #[test]
    fn test_case_04_mixed_project_without_dot_obsidian_but_with_syntax() {
        let dir = tempdir().unwrap();
        create_dir_all(dir.path().join("src")).unwrap();
        create_dir_all(dir.path().join("notes")).unwrap();
        fs::write(dir.path().join("src/lib.rs"), "pub fn compute() {}").unwrap();
        fs::write(dir.path().join("notes/API.md"), "# API\nSee [[Endpoints]] and #dev/api").unwrap();

        let report = detect_project_type(dir.path()).unwrap();
        assert_eq!(report.project_type, DetectedProjectType::Mixed);
        assert!(!report.has_obsidian_dir);
        assert!(report.obsidian_syntax_markers_count >= 2);
        assert_eq!(report.default_view, "code");
        assert!(report.allows_dual_vision());
    }

    #[test]
    fn test_case_05_pure_code_project_with_plain_readme() {
        let dir = tempdir().unwrap();
        create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join("src/utils.rs"), "pub fn help() {}").unwrap();
        fs::write(dir.path().join("README.md"), "# Project\nStandard documentation without wikilinks.").unwrap();

        let report = detect_project_type(dir.path()).unwrap();
        assert_eq!(report.project_type, DetectedProjectType::PureCode);
        assert!(!report.has_obsidian_dir);
        assert_eq!(report.code_files_count, 2);
        assert_eq!(report.markdown_files_count, 1);
        assert_eq!(report.obsidian_syntax_markers_count, 0);
        assert_eq!(report.default_view, "code");
        assert_eq!(report.supported_views, vec!["code".to_string()]);
    }

    #[test]
    fn test_case_06_empty_directory_defaults_to_pure_code() {
        let dir = tempdir().unwrap();
        let report = detect_project_type(dir.path()).unwrap();
        assert_eq!(report.project_type, DetectedProjectType::PureCode);
        assert_eq!(report.code_files_count, 0);
        assert_eq!(report.markdown_files_count, 0);
        assert_eq!(report.default_view, "code");
    }

    #[test]
    fn test_case_07_pruning_ignores_target_and_node_modules() {
        let dir = tempdir().unwrap();
        create_dir_all(dir.path().join("src")).unwrap();
        create_dir_all(dir.path().join("target/debug/build")).unwrap();
        create_dir_all(dir.path().join("node_modules/package")).unwrap();

        fs::write(dir.path().join("src/lib.rs"), "pub fn a() {}").unwrap();
        fs::write(dir.path().join("target/debug/build/temp.rs"), "fn temp() {}").unwrap();
        fs::write(dir.path().join("node_modules/package/index.js"), "module.exports = {}").unwrap();
        fs::write(dir.path().join("node_modules/package/README.md"), "[[IgnoredLink]]").unwrap();

        let report = detect_project_type(dir.path()).unwrap();
        assert_eq!(report.code_files_count, 1); // Only src/lib.rs
        assert_eq!(report.markdown_files_count, 0); // node_modules README ignored
        assert_eq!(report.obsidian_syntax_markers_count, 0);
    }

    #[test]
    fn test_case_08_syntax_marker_counting_comprehensive() {
        let content = r#"---
tags: [knowledge, dev]
aliases: [SystemArchitecture]
---
# Heading Is Not Tag
Here is a [[SimpleWikilink]] and an alias [[Target|Custom Display]].
Transclusion: ![[image.png|400x300]]
Nested tag: #dev/backend/db
Another nested tag: #org/team/lead
Ignored heading: ## Section
Ignored single hashtag: # not_a_tag
"#;
        let count = count_markers_in_text(content);
        // 2 frontmatter (tags, aliases) + 2 wikilinks + 1 transclusion + 2 nested tags = 7 markers
        assert_eq!(count, 7);
    }

    #[test]
    fn test_case_09_invalid_path_error() {
        let non_existent = Path::new("c:/__non_existent_folder_xyz_123__");
        let result = detect_project_type(non_existent);
        assert!(result.is_err());
        match result.unwrap_err() {
            ObsidianError::InvalidRoot(msg) => assert!(msg.contains("does not exist")),
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_case_10_json_serialization_matches_api_contract() {
        let report = ProjectDetectionReport::new(
            DetectedProjectType::Mixed,
            true,
            Some("docs/.obsidian".to_string()),
            15,
            8,
            24,
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"project_type\":\"Mixed\""));
        assert!(json.contains("\"has_obsidian_dir\":true"));
        assert!(json.contains("\"obsidian_dir_path\":\"docs/.obsidian\""));
        assert!(json.contains("\"supported_views\":[\"code\",\"vault\"]"));
        assert!(json.contains("\"default_view\":\"code\""));

        let deserialized: ProjectDetectionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, report);
    }

    #[test]
    fn test_case_11_wikilink_target_helpers() {
        let wl1 = crate::types::WikilinkTarget {
            target: "Architecture.md".to_string(),
            label: Some("System Design".to_string()),
            anchor: Some("Overview".to_string()),
            block_id: None,
            is_block_ref: false,
            raw: "[[Architecture.md#Overview|System Design]]".to_string(),
            line: 42,
            col: 1,
        };
        assert_eq!(wl1.clean_target_name(), "Architecture");
        assert_eq!(wl1.display_label(), "System Design");
        assert!(!wl1.is_self_anchor());

        let wl_self = crate::types::WikilinkTarget {
            target: "".to_string(),
            label: None,
            anchor: Some("Heading".to_string()),
            block_id: None,
            is_block_ref: false,
            raw: "[[#Heading]]".to_string(),
            line: 10,
            col: 1,
        };
        assert!(wl_self.is_self_anchor());
    }

    #[test]
    fn test_case_12_transclusion_media_detection() {
        use crate::types::TransclusionTarget;
        assert!(TransclusionTarget::is_media_extension("diagram.png"));
        assert!(TransclusionTarget::is_media_extension("specs/doc.PDF"));
        assert!(TransclusionTarget::is_media_extension("audio.mp3"));
        assert!(!TransclusionTarget::is_media_extension("chapter1.md"));
        assert!(!TransclusionTarget::is_media_extension("main.rs"));

        let t = TransclusionTarget {
            target: "diagram.png".to_string(),
            label_or_size: Some("600x400".to_string()),
            anchor: None,
            block_id: None,
            is_media: true,
            raw: "![[diagram.png|600x400]]".to_string(),
            line: 12,
            col: 1,
        };
        assert_eq!(t.parse_dimensions(), Some((Some(600), Some(400))));
    }

    #[test]
    fn test_case_13_tag_occurrence_hierarchy() {
        let tag = crate::types::TagOccurrence {
            tag: "team/security/sast".to_string(),
            raw: "#team/security/sast".to_string(),
            line: 5,
            col: 1,
            is_frontmatter: false,
        };
        assert!(tag.is_nested());
        assert_eq!(tag.root_tag(), "team");
        assert_eq!(tag.segments(), vec!["team", "security", "sast"]);
    }

    #[test]
    fn test_case_14_frontmatter_attributes_and_tags() {
        let mut fm = crate::types::FrontmatterData {
            tags: vec!["architecture".to_string(), "backend".to_string()],
            aliases: vec!["CoreServer".to_string()],
            ..Default::default()
        };
        fm.custom_attributes.insert("version".to_string(), "1.2.0".to_string());
        fm.attributes.insert("version".to_string(), serde_json::json!("1.2.0"));

        assert!(fm.has_tag("architecture"));
        assert!(fm.has_tag("#backend"));
        assert!(fm.has_alias("coreserver"));
        assert_eq!(fm.get_str("version"), Some("1.2.0"));
    }
}
