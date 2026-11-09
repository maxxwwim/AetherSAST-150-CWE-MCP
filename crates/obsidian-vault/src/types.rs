//! Core data types, AST structures, project classification reports, and error definitions
//! for the Obsidian Vault engine.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

/// Project classification determined by the automatic detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectedProjectType {
    /// Pure Obsidian knowledge base (notes, wikilinks, attachments, .obsidian folder).
    PureObsidianVault,
    /// Standard software engineering codebase without Obsidian vault characteristics.
    PureCode,
    /// Hybrid workspace containing both active source code and Obsidian documentation.
    Mixed,
}

impl DetectedProjectType {
    /// String representation matching REST API and MCP responses.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PureObsidianVault => "PureObsidianVault",
            Self::PureCode => "PureCode",
            Self::Mixed => "Mixed",
        }
    }

    /// Whether this project type is a pure vault.
    pub fn is_vault(&self) -> bool {
        matches!(self, Self::PureObsidianVault)
    }

    /// Whether this project type is pure code.
    pub fn is_code(&self) -> bool {
        matches!(self, Self::PureCode)
    }

    /// Whether this project type is a mixed code + notes project.
    pub fn is_mixed(&self) -> bool {
        matches!(self, Self::Mixed)
    }

    /// Recommended default cockpit view mode.
    pub fn default_view(&self) -> &'static str {
        match self {
            Self::PureObsidianVault => "vault",
            Self::PureCode | Self::Mixed => "code",
        }
    }

    /// List of available cockpit view modes for this project classification.
    pub fn supported_views(&self) -> Vec<&'static str> {
        match self {
            Self::PureObsidianVault => vec!["vault", "code"],
            Self::Mixed => vec!["code", "vault"],
            Self::PureCode => vec!["code"],
        }
    }
}

/// Comprehensive report returned by `detect_project_type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectDetectionReport {
    /// Classification: PureObsidianVault, PureCode, or Mixed.
    pub project_type: DetectedProjectType,
    /// True if an `.obsidian/` folder was detected at root or at depth <= 2.
    pub has_obsidian_dir: bool,
    /// Relative path to the `.obsidian/` directory if found (e.g., ".obsidian", "docs/.obsidian").
    pub obsidian_dir_path: Option<String>,
    /// Number of identified source code files (.rs, .ts, .py, etc.).
    pub code_files_count: usize,
    /// Number of identified markdown files (.md, .markdown).
    pub markdown_files_count: usize,
    /// Count of Obsidian-specific syntax markers sampled across markdown files.
    pub obsidian_syntax_markers_count: usize,
    /// List of supported view modes in the cockpit (e.g. `["code", "vault"]`).
    pub supported_views: Vec<String>,
    /// Default active view mode on project load (`"code"` or `"vault"`).
    pub default_view: String,
}

impl ProjectDetectionReport {
    /// Constructs a new report with normalized view configurations.
    pub fn new(
        project_type: DetectedProjectType,
        has_obsidian_dir: bool,
        obsidian_dir_path: Option<String>,
        code_files_count: usize,
        markdown_files_count: usize,
        obsidian_syntax_markers_count: usize,
    ) -> Self {
        let supported_views = project_type
            .supported_views()
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let default_view = project_type.default_view().to_string();

        Self {
            project_type,
            has_obsidian_dir,
            obsidian_dir_path,
            code_files_count,
            markdown_files_count,
            obsidian_syntax_markers_count,
            supported_views,
            default_view,
        }
    }

    /// Returns true if the vault vision mode is supported for this project.
    pub fn is_vault_mode_available(&self) -> bool {
        self.supported_views.iter().any(|v| v == "vault")
    }

    /// Returns true if the code vision mode is supported for this project.
    pub fn is_code_mode_available(&self) -> bool {
        self.supported_views.iter().any(|v| v == "code")
    }

    /// Returns true if the project supports dual-vision dynamic switching.
    pub fn allows_dual_vision(&self) -> bool {
        self.supported_views.len() > 1
    }
}

/// Represents an extracted wikilink target from Markdown text (`[[target#anchor|label]]`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WikilinkTarget {
    /// Target note name or path without brackets or pipe (e.g., "Architecture" or "guides/deploy").
    pub target: String,
    /// Optional display alias after pipe (`[[target|label]]`).
    pub label: Option<String>,
    /// Optional heading anchor after hash (`[[target#heading]]`).
    pub anchor: Option<String>,
    /// Optional block reference ID after hash-caret (`[[target#^blockid]]`).
    pub block_id: Option<String>,
    /// True if anchor starts with `^` (block reference).
    pub is_block_ref: bool,
    /// Verbatim unparsed link text (e.g., "[[target#heading|label]]").
    pub raw: String,
    /// 1-indexed line number in source file where link appears.
    pub line: usize,
    /// 1-indexed column number in source file.
    pub col: usize,
}

impl WikilinkTarget {
    /// Returns true if this is a self-referential anchor link (e.g., `[[#Section]]`).
    pub fn is_self_anchor(&self) -> bool {
        self.target.trim().is_empty() && (self.anchor.is_some() || self.block_id.is_some())
    }

    /// Returns the effective display label (label if present, otherwise target).
    pub fn display_label(&self) -> &str {
        if let Some(lbl) = &self.label {
            if !lbl.trim().is_empty() {
                return lbl.trim();
            }
        }
        self.target.trim()
    }

    /// Clean canonical note target without file extension or trailing slash.
    pub fn clean_target_name(&self) -> &str {
        let t = self.target.trim();
        if let Some(stripped) = t.strip_suffix(".md") {
            stripped
        } else {
            t
        }
    }
}

/// Represents an extracted transclusion / embed (`![[target#anchor|size]]`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransclusionTarget {
    /// Embedded target note or media asset path (e.g., "banner.png" or "NoteA").
    pub target: String,
    /// Optional size or display override (e.g., "400" or "400x300").
    pub label_or_size: Option<String>,
    /// Optional heading anchor if transcluding a section (`![[NoteA#Heading]]`).
    pub anchor: Option<String>,
    /// Optional block ID if transcluding a specific block (`![[NoteA#^block1]]`).
    pub block_id: Option<String>,
    /// True if the target matches a known media/attachment file extension.
    pub is_media: bool,
    /// Verbatim unparsed embed text (e.g., "![[banner.png|300]]").
    pub raw: String,
    /// 1-indexed line number in source file.
    pub line: usize,
    /// 1-indexed column number in source file.
    pub col: usize,
}

impl TransclusionTarget {
    /// Known media and binary attachment extensions in Obsidian.
    pub const MEDIA_EXTENSIONS: &'static [&'static str] = &[
        "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp", "ico",
        "pdf", "mp3", "wav", "m4a", "ogg", "3gp", "flac",
        "mp4", "webm", "ogv", "mov", "mkv",
    ];

    /// Determines whether a filename or path corresponds to a media attachment.
    pub fn is_media_extension(path: &str) -> bool {
        let lower = path.to_lowercase();
        let ext = lower.split('.').next_back().unwrap_or("");
        Self::MEDIA_EXTENSIONS.contains(&ext)
    }

    /// Returns display label if present.
    pub fn label(&self) -> Option<&str> {
        self.label_or_size.as_deref()
    }

    /// Parses dimensions formatted as "WIDTH" or "WIDTHxHEIGHT".
    pub fn parse_dimensions(&self) -> Option<(Option<u32>, Option<u32>)> {
        let raw = self.label_or_size.as_ref()?.trim();
        if let Some((w_str, h_str)) = raw.split_once('x') {
            let w = w_str.trim().parse::<u32>().ok();
            let h = h_str.trim().parse::<u32>().ok();
            Some((w, h))
        } else if let Ok(w) = raw.parse::<u32>() {
            Some((Some(w), None))
        } else {
            None
        }
    }
}

/// Represents an extracted tag occurrence (`#tag` or `#nested/tag`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TagOccurrence {
    /// Canonical tag name without leading `#` (e.g., "dev/backend/db").
    pub tag: String,
    /// Verbatim tag text from document (e.g., "#dev/backend/db").
    pub raw: String,
    /// 1-indexed line number where tag appears.
    pub line: usize,
    /// 1-indexed column number where tag appears.
    pub col: usize,
    /// True if extracted from YAML frontmatter rather than note body.
    pub is_frontmatter: bool,
}

impl TagOccurrence {
    /// Returns true if this is a hierarchical / nested tag containing slashes.
    pub fn is_nested(&self) -> bool {
        self.tag.contains('/')
    }

    /// Returns the root category tag (e.g., "dev" for "dev/backend/db").
    pub fn root_tag(&self) -> &str {
        self.tag.split('/').next().unwrap_or(&self.tag)
    }

    /// Returns the sequence of tag segments split by '/'.
    pub fn segments(&self) -> Vec<&str> {
        self.tag.split('/').filter(|s| !s.is_empty()).collect()
    }
}

/// Metadata parsed from YAML frontmatter between `---` fences.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FrontmatterData {
    /// Tags extracted from frontmatter `tags:` or `tag:` fields.
    pub tags: Vec<String>,
    /// Aliases extracted from `aliases:` or `alias:` fields.
    pub aliases: Vec<String>,
    /// Explicit title override if specified in frontmatter (`title:`).
    pub title: Option<String>,
    /// Custom metadata attributes stored as string key-value pairs.
    pub custom_attributes: HashMap<String, String>,
    /// Custom metadata attributes stored as JSON values.
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// Wikilinks extracted from frontmatter fields.
    pub frontmatter_wikilinks: Vec<WikilinkTarget>,
    /// Raw unparsed YAML frontmatter content.
    pub raw_yaml: String,
    /// Total byte length of YAML block + fences.
    pub byte_length: usize,
}

impl FrontmatterData {
    /// Retrieves a string attribute by key.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        if let Some(s) = self.custom_attributes.get(key) {
            return Some(s.as_str());
        }
        self.attributes.get(key).and_then(|v| v.as_str())
    }

    /// Checks if a tag is present in frontmatter tags.
    pub fn has_tag(&self, tag: &str) -> bool {
        let clean = tag.strip_prefix('#').unwrap_or(tag).to_lowercase();
        self.tags.iter().any(|t| t.to_lowercase() == clean)
    }

    /// Checks if an alias is registered in frontmatter aliases.
    pub fn has_alias(&self, alias: &str) -> bool {
        let clean = alias.trim().to_lowercase();
        self.aliases.iter().any(|a| a.trim().to_lowercase() == clean)
    }
}

/// Complete parsed intermediate representation of a Markdown note.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParsedNote {
    /// Relative path within vault jail (e.g., "docs/architecture.md").
    pub relative_path: String,
    /// Clean note name without extension (e.g., "architecture").
    pub name: String,
    /// Title of the note (from frontmatter `title:`, first H1 heading, or filename).
    pub title: String,
    /// Extracted frontmatter if present.
    pub frontmatter: Option<FrontmatterData>,
    /// Outgoing wikilinks extracted from note body and frontmatter.
    pub wikilinks: Vec<WikilinkTarget>,
    /// Outgoing transclusions/embeds.
    pub transclusions: Vec<TransclusionTarget>,
    /// Inline tags extracted from note body and frontmatter.
    pub tags: Vec<TagOccurrence>,
    /// Section headings extracted from note body.
    pub section_headings: Vec<String>,
    /// Total lines in file.
    pub lines_count: usize,
    /// Size in bytes on disk.
    pub byte_size: u64,
    /// Optional raw markdown content (retained for preview or AST caching).
    pub raw_content: Option<String>,
}

/// Type alias for `ParsedNote` providing compatibility with `ParsedMarkdownDoc`.
pub type ParsedMarkdownDoc = ParsedNote;

/// Record of an incoming backlink to a note.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BacklinkRecord {
    /// Path of referring note.
    pub source_path: String,
    /// Title of referring note.
    pub source_title: String,
    /// Line number where link occurs in referring note.
    pub line: usize,
    /// Alias/label used in the reference if any.
    pub label: Option<String>,
    /// Anchor targeted in the reference if any.
    pub anchor: Option<String>,
    /// Whether the link is an embed (`![[...]]`) or regular link (`[[...]]`).
    pub is_transclusion: bool,
}

/// Unified error enum for Obsidian Vault operations conforming to PROJECT.md.
#[derive(Debug, Error)]
pub enum ObsidianError {
    /// Security violation: path traversal attempt outside root jail.
    #[error("Path traversal security violation: {0}")]
    PathTraversal(String),

    /// Security violation: symlink resolves to path outside root jail.
    #[error("Symlink escape security violation: {0}")]
    SymlinkEscape(String),

    /// Generic filesystem I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// YAML frontmatter parsing error.
    #[error("YAML deserialization error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// Target path is invalid, missing, or not a directory.
    #[error("Invalid root directory: {0}")]
    InvalidRoot(String),

    /// Security error from confinement verification.
    #[error("Security confinement violation: {0}")]
    Security(String),

    /// File exceeded the maximum allowable size limit (e.g. 10MB).
    #[error("File '{path}' size ({size_bytes} bytes) exceeds limit ({max_bytes} bytes)")]
    FileTooLarge {
        path: String,
        size_bytes: u64,
        max_bytes: u64,
    },

    /// Generic parsing failure.
    #[error("Obsidian parse error: {0}")]
    Parse(String),
}

impl From<crate::confinement::SecurityError> for ObsidianError {
    fn from(err: crate::confinement::SecurityError) -> Self {
        match err {
            crate::confinement::SecurityError::PathTraversal(p) => ObsidianError::PathTraversal(p),
            crate::confinement::SecurityError::SymlinkEscape {
                symlink_path,
                resolved_path,
                root,
            } => ObsidianError::SymlinkEscape(format!(
                "Symlink '{}' escapes root '{}' to '{}'",
                symlink_path.display(),
                root.display(),
                resolved_path.display()
            )),
            crate::confinement::SecurityError::FileTooLarge {
                path,
                size,
                max_size,
            } => ObsidianError::FileTooLarge {
                path: path.to_string_lossy().to_string(),
                size_bytes: size,
                max_bytes: max_size,
            },
            crate::confinement::SecurityError::IoError { source, .. } => ObsidianError::Io(source),
            other => ObsidianError::Security(other.to_string()),
        }
    }
}
