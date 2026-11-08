use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Normalized Dependency Package representation for SCA
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScaDependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    #[serde(default)]
    pub is_dev: bool,
    #[serde(default)]
    pub manifest_file: String,
}

impl ScaDependency {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        ecosystem: impl Into<String>,
        is_dev: bool,
        manifest_file: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            ecosystem: ecosystem.into(),
            is_dev,
            manifest_file: manifest_file.into(),
        }
    }
}

/// Helper function to strip trailing comments outside of string literals
fn strip_inline_comment(raw: &str) -> &str {
    let mut in_quote = false;
    let mut prev_char = '\0';
    for (idx, ch) in raw.char_indices() {
        if ch == '"' && prev_char != '\\' {
            in_quote = !in_quote;
        } else if ch == '#' && !in_quote {
            return raw[..idx].trim();
        }
        prev_char = ch;
    }
    raw.trim()
}

/// Helper function to parse Cargo.lock TOML content
pub fn parse_cargo_lock_content(content: &str, manifest_path: &str) -> Result<Vec<ScaDependency>, String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // Quick syntax validation for common TOML malformations
    for raw_line in content.lines() {
        let line = strip_inline_comment(raw_line);
        if line.is_empty() {
            continue;
        }

        // Table array header
        if line.starts_with("[[") {
            if !line.ends_with("]]") {
                return Err(format!("Malformed table array header in Cargo.lock: {line}"));
            }
            continue;
        }

        // Standard table header
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(format!("Malformed table header in Cargo.lock: {line}"));
            }
            continue;
        }

        // Key-value pair
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            if key.is_empty() {
                return Err(format!("Empty key in Cargo.lock: {line}"));
            }
            // Check for malformed values like `[[not valid toml`
            if val.starts_with("[[") && !val.ends_with("]]") {
                return Err(format!("Malformed array-of-tables assignment in Cargo.lock: {line}"));
            }
            if val.starts_with('"') && (!val.ends_with('"') || val.len() == 1) {
                return Err(format!("Unterminated string literal in Cargo.lock: {line}"));
            }
        } else if !line.starts_with(']') && !line.starts_with('"') {
            return Err(format!("Unrecognized line syntax in Cargo.lock: {line}"));
        }
    }

    let mut deps = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_source: Option<String> = None;
    let mut in_package_block = false;

    let flush_package = |name_opt: &Option<String>,
                         ver_opt: &Option<String>,
                         src_opt: &Option<String>,
                         out: &mut Vec<ScaDependency>| {
        if let (Some(name), Some(version)) = (name_opt, ver_opt) {
            let is_registry = src_opt
                .as_deref()
                .map_or(false, |s| s.starts_with("registry+") || s.starts_with("git+"));
            if is_registry {
                out.push(ScaDependency {
                    name: name.clone(),
                    version: version.clone(),
                    ecosystem: "crates.io".to_string(),
                    is_dev: false,
                    manifest_file: manifest_path.to_string(),
                });
            }
        }
    };

    for raw_line in content.lines() {
        let line = strip_inline_comment(raw_line);

        if line.is_empty() {
            continue;
        }

        if line == "[[package]]" {
            if in_package_block {
                flush_package(&current_name, &current_version, &current_source, &mut deps);
            }
            in_package_block = true;
            current_name = None;
            current_version = None;
            current_source = None;
            continue;
        } else if line.starts_with("[[") || line.starts_with('[') {
            if in_package_block {
                flush_package(&current_name, &current_version, &current_source, &mut deps);
            }
            in_package_block = false;
            current_name = None;
            current_version = None;
            current_source = None;
            continue;
        }

        if in_package_block {
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim();
                let val = v.trim().trim_matches('"');
                match key {
                    "name" => current_name = Some(val.to_string()),
                    "version" => current_version = Some(val.to_string()),
                    "source" => current_source = Some(val.to_string()),
                    _ => {}
                }
            }
        }
    }

    if in_package_block {
        flush_package(&current_name, &current_version, &current_source, &mut deps);
    }

    Ok(deps)
}

/// Helper function to parse package-lock.json (supporting v1 recursive and v2/v3 flat formats)
pub fn parse_package_lock_content(content: &str, manifest_path: &str) -> Result<Vec<ScaDependency>, String> {
    let json_val: serde_json::Value = serde_json::from_str(content).map_err(|e| e.to_string())?;
    let mut deps = Vec::new();

    // Check v2/v3 "packages" dictionary
    if let Some(packages) = json_val.get("packages").and_then(|p| p.as_object()) {
        for (path, val) in packages {
            if path.is_empty() {
                continue; // Skip root project descriptor
            }

            let name = if let Some(n) = val.get("name").and_then(|s| s.as_str()) {
                n.to_string()
            } else if let Some(idx) = path.rfind("node_modules/") {
                path[idx + "node_modules/".len()..].to_string()
            } else {
                continue;
            };

            if let Some(version) = val.get("version").and_then(|v| v.as_str()) {
                let is_dev = val.get("dev").and_then(|d| d.as_bool()).unwrap_or(false);
                deps.push(ScaDependency {
                    name,
                    version: version.to_string(),
                    ecosystem: "npm".to_string(),
                    is_dev,
                    manifest_file: manifest_path.to_string(),
                });
            }
        }
    } else if let Some(dependencies) = json_val.get("dependencies").and_then(|d| d.as_object()) {
        // v1 recursive "dependencies" dictionary
        fn parse_v1_deps(
            map: &serde_json::Map<String, serde_json::Value>,
            manifest_path: &str,
            out: &mut Vec<ScaDependency>,
        ) {
            for (name, val) in map {
                if let Some(version) = val.get("version").and_then(|v| v.as_str()) {
                    let is_dev = val.get("dev").and_then(|d| d.as_bool()).unwrap_or(false);
                    out.push(ScaDependency {
                        name: name.clone(),
                        version: version.to_string(),
                        ecosystem: "npm".to_string(),
                        is_dev,
                        manifest_file: manifest_path.to_string(),
                    });
                }
                if let Some(nested) = val.get("dependencies").and_then(|d| d.as_object()) {
                    parse_v1_deps(nested, manifest_path, out);
                }
            }
        }

        parse_v1_deps(dependencies, manifest_path, &mut deps);
    }

    Ok(deps)
}

/// Helper function to parse composer.lock JSON content (packages & packages-dev)
pub fn parse_composer_lock_content(content: &str, manifest_path: &str) -> Result<Vec<ScaDependency>, String> {
    let json_val: serde_json::Value = serde_json::from_str(content).map_err(|e| e.to_string())?;
    let mut deps = Vec::new();

    let parse_pkg_list = |arr: &serde_json::Value, is_dev: bool, out: &mut Vec<ScaDependency>| {
        if let Some(packages) = arr.as_array() {
            for pkg in packages {
                if let (Some(name), Some(version)) = (
                    pkg.get("name").and_then(|n| n.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) {
                    out.push(ScaDependency {
                        name: name.to_string(),
                        version: version.trim_start_matches('v').to_string(),
                        ecosystem: "Packagist".to_string(),
                        is_dev,
                        manifest_file: manifest_path.to_string(),
                    });
                }
            }
        }
    };

    if let Some(packages) = json_val.get("packages") {
        parse_pkg_list(packages, false, &mut deps);
    }
    if let Some(packages_dev) = json_val.get("packages-dev") {
        parse_pkg_list(packages_dev, true, &mut deps);
    }

    Ok(deps)
}

/// Parse a lockfile from disk by path, dispatching based on file name
pub fn parse_lockfile_path<P: AsRef<Path>>(path: P) -> Result<Vec<ScaDependency>, String> {
    let p = path.as_ref();
    let content = fs::read_to_string(p).map_err(|e| format!("Failed to read lockfile {}: {}", p.display(), e))?;
    let filename = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let manifest_str = p.to_string_lossy().to_string();

    if filename.eq_ignore_ascii_case("Cargo.lock") {
        parse_cargo_lock_content(&content, &manifest_str)
    } else if filename.eq_ignore_ascii_case("package-lock.json") {
        parse_package_lock_content(&content, &manifest_str)
    } else if filename.eq_ignore_ascii_case("composer.lock") {
        parse_composer_lock_content(&content, &manifest_str)
    } else {
        Err(format!("Unsupported lockfile type: {}", filename))
    }
}

/// Scan a project directory for all supported lockfiles (Cargo.lock, package-lock.json, composer.lock)
pub fn scan_project_lockfiles<P: AsRef<Path>>(project_root: P) -> Result<Vec<ScaDependency>, String> {
    let root = project_root.as_ref();
    let mut all_deps = Vec::new();
    let lockfile_names = ["Cargo.lock", "package-lock.json", "composer.lock"];

    for name in &lockfile_names {
        let p = root.join(name);
        if p.is_file() {
            if let Ok(deps) = parse_lockfile_path(&p) {
                all_deps.extend(deps);
            }
        }
    }

    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if dir_name == "target" || dir_name == "node_modules" || dir_name == ".git" {
                    continue;
                }
                for name in &lockfile_names {
                    let sub_p = path.join(name);
                    if sub_p.is_file() {
                        if let Ok(deps) = parse_lockfile_path(&sub_p) {
                            all_deps.extend(deps);
                        }
                    }
                }
            }
        }
    }

    Ok(all_deps)
}
