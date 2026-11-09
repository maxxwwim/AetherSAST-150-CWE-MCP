//! Obsidian Markdown parser handling CommonMark code/comment masking,
//! wikilinks (`[[note]]`), alias wikilinks (`[[note|label]]`),
//! section anchors (`[[note#heading]]`), transclusions (`![[...] ]`),
//! inline & nested tags (`#tag/subtag`), and YAML frontmatter extraction.

use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

use crate::types::{
    FrontmatterData, ParsedNote, TagOccurrence, TransclusionTarget, WikilinkTarget,
};

/// Regex matching YAML frontmatter at the very beginning of the document:
/// Starts with `---` on line 1, ends with `---` or `...` on its own line.
static FRONTMATTER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A---(?:\r?\n)([\s\S]*?)(?:\r?\n)(?:---|---|\.\.\.)(?:\r?\n)").unwrap()
});

/// Unified regex for wikilinks and transclusions without lookaround.
/// Group 1: optional escape backslash `\`
/// Group 2: optional transclusion `!`
/// Group 3: target
/// Group 4: optional anchor
/// Group 5: optional label / display alias
static LINK_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\\)?(!)?\[\[([^\]|#\r\n]*)(?:#([^\]|\r\n]+))?(?:\|([^\]\r\n]+))?\]\]").unwrap()
});

/// Replaces code fences, inline code, and HTML comments with whitespace of identical byte length.
/// Preserves newline characters ('\n' and '\r') so line numbers and column offsets remain 100% accurate.
pub fn mask_markdown_content(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut output = input.as_bytes().to_vec();
    let mut i = 0;

    while i < len {
        // 1. HTML Comments: <!-- ... -->
        if i + 4 <= len && &bytes[i..i + 4] == b"<!--" {
            let start = i;
            i += 4;
            while i + 3 <= len && &bytes[i..i + 3] != b"-->" {
                i += 1;
            }
            let end = if i + 3 <= len { i + 3 } else { len };
            mask_region(&mut output, start, end);
            i = end;
            continue;
        }

        // 2. Fenced Code Blocks: ``` or ~~~ at line start (or up to 3 leading spaces)
        if i == 0 || bytes[i - 1] == b'\n' {
            let mut ws_count = 0;
            while i + ws_count < len
                && (bytes[i + ws_count] == b' ' || bytes[i + ws_count] == b'\t')
                && ws_count < 4
            {
                ws_count += 1;
            }
            let fence_start = i + ws_count;
            if fence_start + 3 <= len
                && (bytes[fence_start..fence_start + 3] == *b"```"
                    || bytes[fence_start..fence_start + 3] == *b"~~~")
            {
                let fence_char = bytes[fence_start];
                let mut fence_len = 0;
                while fence_start + fence_len < len && bytes[fence_start + fence_len] == fence_char
                {
                    fence_len += 1;
                }
                // Skip info string until newline
                let mut content_start = fence_start + fence_len;
                while content_start < len && bytes[content_start] != b'\n' {
                    content_start += 1;
                }
                if content_start < len {
                    content_start += 1;
                }

                // Find closing fence
                let mut scan = content_start;
                let mut closed = false;
                let mut close_end = len;
                while scan < len {
                    if scan == 0 || bytes[scan - 1] == b'\n' {
                        let mut c_ws = 0;
                        while scan + c_ws < len
                            && (bytes[scan + c_ws] == b' ' || bytes[scan + c_ws] == b'\t')
                            && c_ws < 4
                        {
                            c_ws += 1;
                        }
                        let c_start = scan + c_ws;
                        let mut c_len = 0;
                        while c_start + c_len < len && bytes[c_start + c_len] == fence_char {
                            c_len += 1;
                        }
                        if c_len >= fence_len {
                            let mut line_end = c_start + c_len;
                            while line_end < len && bytes[line_end] != b'\n' {
                                line_end += 1;
                            }
                            if line_end < len {
                                line_end += 1;
                            }
                            close_end = line_end;
                            closed = true;
                            break;
                        }
                    }
                    scan += 1;
                }
                let end = if closed { close_end } else { len };
                mask_region(&mut output, fence_start, end);
                i = end;
                continue;
            }
        }

        // 3. Inline Code: `...` (excluding escaped backticks)
        if bytes[i] == b'`' && (i == 0 || bytes[i - 1] != b'\\') {
            let mut backtick_count = 0;
            while i + backtick_count < len && bytes[i + backtick_count] == b'`' {
                backtick_count += 1;
            }
            let start = i;
            let mut scan = i + backtick_count;
            let mut found_close = false;
            while scan < len {
                if bytes[scan] == b'`' && (scan == 0 || bytes[scan - 1] != b'\\') {
                    let mut close_count = 0;
                    while scan + close_count < len && bytes[scan + close_count] == b'`' {
                        close_count += 1;
                    }
                    if close_count == backtick_count {
                        mask_region(&mut output, start, scan + close_count);
                        i = scan + close_count;
                        found_close = true;
                        break;
                    }
                    scan += close_count;
                } else {
                    scan += 1;
                }
            }
            if found_close {
                continue;
            }
        }

        i += 1;
    }

    String::from_utf8(output).unwrap_or_else(|_| input.to_string())
}

#[inline]
fn mask_region(output: &mut [u8], start: usize, end: usize) {
    let limit = end.min(output.len());
    for b in &mut output[start..limit] {
        if *b != b'\n' && *b != b'\r' {
            *b = b' ';
        }
    }
}

/// Extracts YAML frontmatter between `---` fences at the beginning of the file.
pub fn extract_frontmatter(content: &str) -> Option<FrontmatterData> {
    let caps = FRONTMATTER_REGEX.captures(content)?;
    let yaml_str = caps.get(1)?.as_str();
    let total_match = caps.get(0)?;
    let byte_length = total_match.end();

    let mut frontmatter = FrontmatterData {
        raw_yaml: yaml_str.to_string(),
        byte_length,
        ..Default::default()
    };

    // 1. Parse YAML mapping with serde_yaml::Value (preprocessed for unquoted # tags)
    let preprocessed = preprocess_yaml(yaml_str);
    if let Ok(serde_yaml::Value::Mapping(map)) = serde_yaml::from_str::<serde_yaml::Value>(&preprocessed) {
        for (k, v) in map {
            let key_str = match k {
                serde_yaml::Value::String(s) => s,
                _ => continue,
            };

            match key_str.as_str() {
                "tags" | "tag" => {
                    frontmatter.tags.extend(extract_yaml_tags(&v));
                }
                "aliases" | "alias" => {
                    frontmatter.aliases.extend(extract_yaml_aliases(&v));
                }
                "title" => {
                    if let serde_yaml::Value::String(t) = v {
                        frontmatter.title = Some(t.trim().to_string());
                    }
                }
                other => {
                    let val_str = match &v {
                        serde_yaml::Value::String(s) => s.clone(),
                        serde_yaml::Value::Number(n) => n.to_string(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        _ => format!("{:?}", v),
                    };
                    frontmatter
                        .custom_attributes
                        .insert(other.to_string(), val_str);

                    if let Ok(json_val) = serde_json::to_value(&v) {
                        frontmatter.attributes.insert(other.to_string(), json_val);
                    }
                }
            }
        }
    }

    // 2. Extract wikilinks embedded in YAML frontmatter fields
    for cap in LINK_REGEX.captures_iter(yaml_str) {
        if cap.get(1).is_some() {
            // Escaped with backslash
            continue;
        }
        let raw = cap.get(0).map_or("", |m| m.as_str()).to_string();
        let target = cap.get(3).map_or("", |m| m.as_str()).trim().to_string();
        let anchor = cap.get(4).map(|m| m.as_str().trim().to_string());
        let label = cap.get(5).map(|m| m.as_str().trim().to_string());
        let is_block_ref = anchor.as_ref().is_some_and(|a| a.starts_with('^'));
        let block_id = if is_block_ref {
            anchor.as_ref().and_then(|a| a.strip_prefix('^')).map(|s| s.to_string())
        } else {
            None
        };

        if !target.is_empty() {
            frontmatter.frontmatter_wikilinks.push(WikilinkTarget {
                raw,
                target,
                label,
                anchor,
                block_id,
                is_block_ref,
                line: 1, // Frontmatter line
                col: 1,
            });
        }
    }

    Some(frontmatter)
}

fn preprocess_yaml(yaml: &str) -> String {
    let mut out = String::with_capacity(yaml.len() + 32);
    for line in yaml.lines() {
        let trimmed_start = line.trim_start();
        if trimmed_start.starts_with("- #") {
            let indent = &line[..line.len() - trimmed_start.len()];
            let tag_val = trimmed_start.strip_prefix("- #").unwrap().trim();
            out.push_str(indent);
            out.push_str("- \"#");
            out.push_str(tag_val);
            out.push_str("\"\n");
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn extract_yaml_tags(val: &serde_yaml::Value) -> Vec<String> {
    let mut tags = Vec::new();
    match val {
        serde_yaml::Value::String(s) => {
            for part in s.split(',') {
                let clean = part.trim().trim_start_matches('#');
                if !clean.is_empty() {
                    tags.push(clean.to_string());
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                if let serde_yaml::Value::String(s) = item {
                    let clean = s.trim().trim_start_matches('#');
                    if !clean.is_empty() {
                        tags.push(clean.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    tags
}

fn extract_yaml_aliases(val: &serde_yaml::Value) -> Vec<String> {
    let mut aliases = Vec::new();
    match val {
        serde_yaml::Value::String(s) => {
            for part in s.split(',') {
                let clean = part.trim();
                if !clean.is_empty() {
                    aliases.push(clean.to_string());
                }
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                if let serde_yaml::Value::String(s) = item {
                    let clean = s.trim();
                    if !clean.is_empty() {
                        aliases.push(clean.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    aliases
}

/// Parses wikilinks (`[[...]]`) and transclusions (`![[...]]`) from masked markdown.
pub fn parse_wikilinks_and_transclusions(
    masked_content: &str,
    start_byte_offset: usize,
) -> (Vec<WikilinkTarget>, Vec<TransclusionTarget>) {
    let mut wikilinks = Vec::new();
    let mut transclusions = Vec::new();

    let line_starts = compute_line_starts(masked_content);

    for cap in LINK_REGEX.captures_iter(&masked_content[start_byte_offset..]) {
        // Group 1: escape backslash
        if cap.get(1).is_some() {
            continue;
        }

        let m = cap.get(0).unwrap();
        let abs_start = start_byte_offset + m.start();
        let (line, col) = byte_to_line_col(&line_starts, abs_start);

        let is_transclusion = cap.get(2).is_some();
        let raw = m.as_str().to_string();
        let target = cap.get(3).map_or("", |c| c.as_str()).trim().to_string();
        let anchor = cap.get(4).map(|c| c.as_str().trim().to_string());
        let label = cap.get(5).map(|c| c.as_str().trim().to_string());

        if target.is_empty() && anchor.is_none() {
            continue;
        }

        if is_transclusion {
            let ext = Path::new(&target)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            let is_media = TransclusionTarget::is_media_extension(ext);
            let block_id = if anchor.as_ref().is_some_and(|a| a.starts_with('^')) {
                anchor.as_ref().and_then(|a| a.strip_prefix('^')).map(|s| s.to_string())
            } else {
                None
            };

            transclusions.push(TransclusionTarget {
                raw,
                target,
                label_or_size: label,
                anchor,
                block_id,
                is_media,
                line,
                col,
            });
        } else {
            let is_block_ref = anchor.as_ref().is_some_and(|a| a.starts_with('^'));
            let block_id = if is_block_ref {
                anchor.as_ref().and_then(|a| a.strip_prefix('^')).map(|s| s.to_string())
            } else {
                None
            };

            wikilinks.push(WikilinkTarget {
                raw,
                target,
                label,
                anchor,
                block_id,
                is_block_ref,
                line,
                col,
            });
        }
    }

    (wikilinks, transclusions)
}

/// Parses inline tags (`#tag` or `#nested/tag/subtag`) from masked content.
pub fn parse_inline_tags(masked_content: &str, start_byte_offset: usize) -> Vec<TagOccurrence> {
    let mut tags = Vec::new();
    let line_starts = compute_line_starts(masked_content);
    let bytes = masked_content.as_bytes();
    let len = bytes.len();
    let mut i = start_byte_offset;

    while i < len {
        if bytes[i] == b'#' {
            // Check preceding boundary: must be at start, or preceded by whitespace / allowed punctuation
            let valid_preceding = if i == 0 {
                true
            } else {
                let prev = bytes[i - 1];
                prev == b' '
                    || prev == b'\t'
                    || prev == b'\n'
                    || prev == b'\r'
                    || prev == b'('
                    || prev == b'['
                    || prev == b'{'
                    || prev == b'"'
                    || prev == b'\''
                    || prev == b'<'
                    || prev == b','
                    || prev == b';'
            };

            if valid_preceding && i + 1 < len {
                // Must not be followed by space or another '#' (which would be markdown heading)
                let next = bytes[i + 1];
                if next != b' ' && next != b'\t' && next != b'#' && next != b'\n' && next != b'\r' {
                    // Extract tag candidate
                    let tag_start = i + 1;
                    let mut tag_end = tag_start;

                    // Scan tag chars
                    while tag_end < len {
                        let c = bytes[tag_end];
                        if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'/' || c >= 128 {
                            tag_end += 1;
                        } else {
                            break;
                        }
                    }

                    if tag_end > tag_start {
                        let candidate = &masked_content[tag_start..tag_end];
                        // Clean trailing slashes or hyphens
                        let clean_tag = candidate.trim_end_matches(['/', '-']);

                        if !clean_tag.is_empty() {
                            // Tag validation:
                            // 1. Must not be pure numeric (e.g. #12345)
                            let is_all_numeric = clean_tag
                                .split('/')
                                .all(|seg| seg.chars().all(|c| c.is_ascii_digit()));

                            // 2. First character of each segment must be a letter, underscore, or non-ascii
                            let first_char = clean_tag.chars().next().unwrap_or('0');
                            let valid_start = first_char.is_alphabetic() || first_char == '_';

                            // 3. No consecutive slashes
                            let no_empty_segments = !clean_tag.split('/').any(|seg| seg.is_empty());

                            if !is_all_numeric && valid_start && no_empty_segments {
                                let (line, col) = byte_to_line_col(&line_starts, i);
                                tags.push(TagOccurrence {
                                    tag: clean_tag.to_string(),
                                    raw: format!("#{}", clean_tag),
                                    line,
                                    col,
                                    is_frontmatter: false,
                                });
                            }
                        }
                    }
                    i = tag_end;
                    continue;
                }
            }
        }
        i += 1;
    }

    tags
}

/// Extracts section headings from markdown (`# Heading`, `## Section`, etc.).
pub fn extract_headings(masked: &str, start_offset: usize) -> Vec<String> {
    let mut headings = Vec::new();
    let slice = &masked[start_offset..];
    for line in slice.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            let mut h_level = 0;
            let bytes = trimmed.as_bytes();
            while h_level < bytes.len() && bytes[h_level] == b'#' {
                h_level += 1;
            }
            if (1..=6).contains(&h_level)
                && h_level < bytes.len()
                && (bytes[h_level] == b' ' || bytes[h_level] == b'\t')
            {
                let title = trimmed[h_level..].trim().to_string();
                if !title.is_empty() {
                    headings.push(title);
                }
            }
        }
    }
    headings
}

/// Parses an entire markdown document, returning structured `ParsedNote`.
pub fn parse_markdown(content: &str, file_path: &Path) -> ParsedNote {
    let byte_size = content.len() as u64;
    let lines_count = content.lines().count().max(1);

    // 1. Extract YAML frontmatter from unmasked content at offset 0
    let frontmatter = extract_frontmatter(content);
    let start_offset = frontmatter.as_ref().map_or(0, |fm| fm.byte_length);

    // 2. Mask code blocks, inline code, HTML comments
    let masked = mask_markdown_content(content);

    // 3. Extract wikilinks and transclusions from masked text
    let (mut wikilinks, transclusions) = parse_wikilinks_and_transclusions(&masked, start_offset);

    // Append frontmatter wikilinks if present
    if let Some(ref fm) = frontmatter {
        wikilinks.extend(fm.frontmatter_wikilinks.clone());
    }

    // 4. Extract inline tags
    let mut tags = parse_inline_tags(&masked, start_offset);

    // Append frontmatter tags
    if let Some(ref fm) = frontmatter {
        for t in &fm.tags {
            tags.push(TagOccurrence {
                tag: t.clone(),
                raw: format!("#{}", t),
                line: 1,
                col: 1,
                is_frontmatter: true,
            });
        }
    }

    // 5. Extract section headings (# Heading)
    let section_headings = extract_headings(&masked, start_offset);

    // 6. Name and Title determination
    let clean_path = file_path.to_string_lossy().replace('\\', "/");
    let name = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Untitled")
        .to_string();

    let title = frontmatter
        .as_ref()
        .and_then(|fm| fm.title.clone())
        .or_else(|| section_headings.first().cloned())
        .unwrap_or_else(|| name.clone());

    ParsedNote {
        relative_path: clean_path,
        name,
        title,
        frontmatter,
        wikilinks,
        transclusions,
        tags,
        section_headings,
        lines_count,
        byte_size,
        raw_content: Some(content.to_string()),
    }
}

fn compute_line_starts(s: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (idx, b) in s.bytes().enumerate() {
        if b == b'\n' {
            starts.push(idx + 1);
        }
    }
    starts
}

fn byte_to_line_col(line_starts: &[usize], byte_offset: usize) -> (usize, usize) {
    match line_starts.binary_search(&byte_offset) {
        Ok(line_idx) => (line_idx + 1, 1),
        Err(line_idx) => {
            let actual_line = line_idx;
            let col = byte_offset - line_starts[actual_line - 1] + 1;
            (actual_line, col)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_masking_code_blocks_and_comments() {
        let input = "Normal text [[RealLink]]\n```rust\nlet x = \"[[FakeLink]]\";\n#not_a_tag\n```\n<!-- [[CommentLink]] -->\n`[[InlineFake]]` and `#fake`\nAfter #realtag";
        let masked = mask_markdown_content(input);

        assert_eq!(masked.len(), input.len(), "Byte length must be preserved");
        assert_eq!(
            masked.lines().count(),
            input.lines().count(),
            "Line count must be preserved"
        );

        let doc = parse_markdown(input, Path::new("test.md"));
        let link_targets: Vec<&str> = doc.wikilinks.iter().map(|w| w.target.as_str()).collect();
        assert_eq!(link_targets, vec!["RealLink"], "Only RealLink should be extracted");

        let tags: Vec<&str> = doc.tags.iter().map(|t| t.tag.as_str()).collect();
        assert_eq!(tags, vec!["realtag"], "Only realtag should be extracted");
    }

    #[test]
    fn test_wikilink_variants() {
        let input = r#"
[[SimpleNote]]
[[Folder/NestedNote]]
[[Note With Spaces]]
[[Note|Alias Label]]
[[Note#Heading Section]]
[[Note#Heading Section|Alias Label]]
[[#Self Heading]]
[[#Self Heading|Self Label]]
[[Note#^blockid123]]
[[Note#^blockid123|Block Label]]
\[\[EscapedLink\]\]
[[ ]]
"#;
        let doc = parse_markdown(input, Path::new("test.md"));
        assert_eq!(doc.wikilinks.len(), 10);

        // 1. Simple
        assert_eq!(doc.wikilinks[0].target, "SimpleNote");
        assert_eq!(doc.wikilinks[0].label, None);
        assert_eq!(doc.wikilinks[0].anchor, None);

        // 2. Folder
        assert_eq!(doc.wikilinks[1].target, "Folder/NestedNote");

        // 3. Spaces
        assert_eq!(doc.wikilinks[2].target, "Note With Spaces");

        // 4. Alias
        assert_eq!(doc.wikilinks[3].target, "Note");
        assert_eq!(doc.wikilinks[3].label.as_deref(), Some("Alias Label"));

        // 5. Heading
        assert_eq!(doc.wikilinks[4].target, "Note");
        assert_eq!(doc.wikilinks[4].anchor.as_deref(), Some("Heading Section"));
        assert!(!doc.wikilinks[4].is_block_ref);

        // 6. Heading + Alias
        assert_eq!(doc.wikilinks[5].target, "Note");
        assert_eq!(doc.wikilinks[5].anchor.as_deref(), Some("Heading Section"));
        assert_eq!(doc.wikilinks[5].label.as_deref(), Some("Alias Label"));

        // 7. Self heading
        assert_eq!(doc.wikilinks[6].target, "");
        assert_eq!(doc.wikilinks[6].anchor.as_deref(), Some("Self Heading"));

        // 8. Self heading + label
        assert_eq!(doc.wikilinks[7].target, "");
        assert_eq!(doc.wikilinks[7].anchor.as_deref(), Some("Self Heading"));
        assert_eq!(doc.wikilinks[7].label.as_deref(), Some("Self Label"));

        // 9. Block ref
        assert_eq!(doc.wikilinks[8].target, "Note");
        assert_eq!(doc.wikilinks[8].anchor.as_deref(), Some("^blockid123"));
        assert_eq!(doc.wikilinks[8].block_id.as_deref(), Some("blockid123"));
        assert!(doc.wikilinks[8].is_block_ref);

        // 10. Block ref + label
        assert_eq!(doc.wikilinks[9].target, "Note");
        assert_eq!(doc.wikilinks[9].anchor.as_deref(), Some("^blockid123"));
        assert_eq!(doc.wikilinks[9].block_id.as_deref(), Some("blockid123"));
        assert!(doc.wikilinks[9].is_block_ref);
        assert_eq!(doc.wikilinks[9].label.as_deref(), Some("Block Label"));
    }

    #[test]
    fn test_transclusions_and_attachments() {
        let input = r#"
![[EmbeddedNote]]
![[EmbeddedNote#Section]]
![[image.png]]
![[assets/photo.jpg|400x300]]
![[audio.mp3]]
![[document.pdf]]
"#;
        let doc = parse_markdown(input, Path::new("test.md"));
        assert_eq!(doc.transclusions.len(), 6);

        // Note embed
        assert_eq!(doc.transclusions[0].target, "EmbeddedNote");
        assert!(!doc.transclusions[0].is_media);

        // Section embed
        assert_eq!(doc.transclusions[1].target, "EmbeddedNote");
        assert_eq!(doc.transclusions[1].anchor.as_deref(), Some("Section"));
        assert!(!doc.transclusions[1].is_media);

        // Image embed
        assert_eq!(doc.transclusions[2].target, "image.png");
        assert!(doc.transclusions[2].is_media);

        // Image with dimensions
        assert_eq!(doc.transclusions[3].target, "assets/photo.jpg");
        assert!(doc.transclusions[3].is_media);
        assert_eq!(doc.transclusions[3].label_or_size.as_deref(), Some("400x300"));

        // Audio
        assert_eq!(doc.transclusions[4].target, "audio.mp3");
        assert!(doc.transclusions[4].is_media);

        // PDF
        assert_eq!(doc.transclusions[5].target, "document.pdf");
        assert!(doc.transclusions[5].is_media);
    }

    #[test]
    fn test_tag_rules_and_boundary_conditions() {
        let input = r#"
#simple #nested/tag/subtag #développement #café
# Header 1 (not a tag)
https://crates.io/crates#anchor (not a tag)
#12345 (pure numeric, not a tag)
#v1.0.0 (tag is v1)
#dev/ (trailing slash)
(#paren_tag) [#bracket_tag]
"#;
        let doc = parse_markdown(input, Path::new("test.md"));
        let tags: Vec<&str> = doc.tags.iter().map(|t| t.tag.as_str()).collect();

        assert!(tags.contains(&"simple"), "Should contain #simple");
        assert!(tags.contains(&"nested/tag/subtag"), "Should contain #nested/tag/subtag");
        assert!(tags.contains(&"développement"), "Should contain #développement");
        assert!(tags.contains(&"café"), "Should contain #café");
        assert!(tags.contains(&"v1"), "Should contain #v1");
        assert!(tags.contains(&"paren_tag"), "Should contain #paren_tag");
        assert!(tags.contains(&"bracket_tag"), "Should contain #bracket_tag");

        // Disallowed
        assert!(!tags.contains(&"Header"), "Header 1 is not a tag");
        assert!(!tags.contains(&"12345"), "12345 is not a tag");
        assert!(!tags.contains(&"anchor"), "URL anchor is not a tag");
    }

    #[test]
    fn test_frontmatter_extraction() {
        let input = r#"---
title: "Custom Document Title"
aliases:
  - ArchSpec
  - Blueprint
tags:
  - #tag1
  - tag2
  - dev/rust
author: "Alice"
related: "[[LinkedFromFM]]"
---
# Main Content
[[BodyLink]]
"#;
        let doc = parse_markdown(input, Path::new("test.md"));
        assert!(doc.frontmatter.is_some());
        let fm = doc.frontmatter.unwrap();

        assert_eq!(fm.title.as_deref(), Some("Custom Document Title"));
        assert_eq!(fm.aliases, vec!["ArchSpec", "Blueprint"]);
        assert_eq!(fm.tags, vec!["tag1", "tag2", "dev/rust"]);
        assert_eq!(
            fm.custom_attributes.get("author").map(|s| s.as_str()),
            Some("Alice")
        );

        // Wikilink inside frontmatter field
        let fm_links: Vec<&str> = fm
            .frontmatter_wikilinks
            .iter()
            .map(|w| w.target.as_str())
            .collect();
        assert_eq!(fm_links, vec!["LinkedFromFM"]);

        // Total wikilinks in doc
        let total_links: Vec<&str> = doc.wikilinks.iter().map(|w| w.target.as_str()).collect();
        assert!(total_links.contains(&"BodyLink"));
        assert!(total_links.contains(&"LinkedFromFM"));
    }

    #[test]
    fn test_frontmatter_edge_cases() {
        // Line 2 start (invalid frontmatter)
        let invalid_start = "\n---\ntags: [tag1]\n---\n";
        let doc1 = parse_markdown(invalid_start, Path::new("test.md"));
        assert!(doc1.frontmatter.is_none());

        // Unclosed frontmatter
        let unclosed = "---\ntitle: unclosed\n# Heading";
        let doc2 = parse_markdown(unclosed, Path::new("test.md"));
        assert!(doc2.frontmatter.is_none());

        // Malformed YAML syntax
        let malformed = "---\ntitle: \"unclosed quote\ntags: [a, b]\n---\n";
        let doc3 = parse_markdown(malformed, Path::new("test.md"));
        assert!(
            doc3.frontmatter.is_some(),
            "Must gracefully recover from malformed YAML"
        );
    }
}
