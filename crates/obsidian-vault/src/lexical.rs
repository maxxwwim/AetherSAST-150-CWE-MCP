use std::path::{Component, Path, PathBuf, Prefix};

use crate::error::SecurityError;

/// Default maximum path depth to prevent deep nesting traversal issues.
pub const MAX_PATH_DEPTH: usize = 32;

/// Whitelisted file extensions permitted for raw binary/media streaming.
pub const ALLOWED_RAW_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "tiff", "pdf", "json", "md",
    "markdown", "txt", "csv",
];

/// Performs lexical validation on an input string without accessing the filesystem.
///
/// Rejects:
/// - Null bytes (`\0`)
/// - URL protocols (`http://`, `file://`, etc.)
/// - UNC network paths (`\\server\share`, `//server/share`)
/// - Windows drive letters (`C:`)
/// - Parent directory traversal (`..`)
pub fn validate_lexical_path(path_str: &str) -> Result<(), SecurityError> {
    // 1. Null byte check
    if path_str.as_bytes().contains(&0) || path_str.contains('\0') {
        return Err(SecurityError::NullByteDetected(path_str.to_string()));
    }

    // 2. URL scheme check (e.g. http://, https://, file://, ftp://)
    if let Some(pos) = path_str.find("://") {
        let scheme = &path_str[..pos];
        if !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            return Err(SecurityError::UrlSchemeProhibited(path_str.to_string()));
        }
    }

    // 3. UNC path check (forward slashes or backslashes)
    if path_str.starts_with(r"\\") || path_str.starts_with("//") {
        return Err(SecurityError::UncPathProhibited(path_str.to_string()));
    }

    // 4. Drive letter check (e.g. "C:foo", "D:\bar", or embedded "/c:/")
    let bytes = path_str.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(SecurityError::DriveLetterProhibited(path_str.to_string()));
    }
    if path_str.contains(":/") || path_str.contains(r":\") {
        return Err(SecurityError::DriveLetterProhibited(path_str.to_string()));
    }

    // 5. Component-by-component traversal inspection
    let p = Path::new(path_str);
    let mut depth: usize = 0;
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                return Err(SecurityError::PathTraversal(path_str.to_string()));
            }
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::VerbatimUNC(_, _) | Prefix::UNC(_, _) => {
                    return Err(SecurityError::UncPathProhibited(path_str.to_string()));
                }
                Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {
                    return Err(SecurityError::DriveLetterProhibited(path_str.to_string()));
                }
                _ => {
                    return Err(SecurityError::InvalidPrefix(path_str.to_string()));
                }
            },
            Component::Normal(_) => {
                depth += 1;
                if depth > MAX_PATH_DEPTH {
                    return Err(SecurityError::DepthExceeded {
                        depth,
                        max: MAX_PATH_DEPTH,
                    });
                }
            }
            _ => {}
        }
    }

    Ok(())
}

/// Sanitizes a relative path string extracted from markdown (e.g. wikilink target).
///
/// Verifies lexical safety, strips leading slashes, normalizes separators,
/// and returns a clean `PathBuf`.
pub fn sanitize_relative_path(raw_path: &str) -> Result<PathBuf, SecurityError> {
    let trimmed = raw_path.trim();
    validate_lexical_path(trimmed)?;

    // Strip any leading slashes or dots
    let clean = trimmed
        .trim_start_matches('/')
        .trim_start_matches('\\')
        .trim_start_matches("./");

    if clean.is_empty() {
        return Ok(PathBuf::new());
    }

    // Re-validate clean slice
    validate_lexical_path(clean)?;

    let mut out = PathBuf::new();
    for segment in clean.split(['/', '\\']) {
        let seg_trimmed = segment.trim();
        if seg_trimmed.is_empty() || seg_trimmed == "." {
            continue;
        }
        if seg_trimmed == ".." {
            return Err(SecurityError::PathTraversal(raw_path.to_string()));
        }
        out.push(seg_trimmed);
    }

    Ok(out)
}

/// Strictly validates untrusted client path strings without touching the filesystem.
///
/// Rejects:
/// - Empty paths or paths consisting only of whitespace
/// - Null bytes (`\0`)
/// - Absolute paths (`Path::is_absolute()`, or starting with `/` or `\`)
/// - UNC network paths (`\\`, `//`) and Windows device paths (`\\?\`, `\\.\`)
/// - Windows drive letters (`C:`, `:/`, `:\`)
/// - URL schemes (`://`)
/// - Parent directory traversal (`..`)
/// - Path nesting depth exceeding `MAX_PATH_DEPTH` (32)
///
/// Normalizes and returns a clean relative `PathBuf`.
pub fn validate_client_relative_path(input: &str) -> Result<PathBuf, SecurityError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SecurityError::PathTraversal("Empty path is prohibited".to_string()));
    }

    // 1. Null byte check
    if trimmed.as_bytes().contains(&0) || trimmed.contains('\0') {
        return Err(SecurityError::NullByteDetected(input.to_string()));
    }

    // 2. URL scheme check (e.g. http://, https://, file://, ftp://)
    if let Some(pos) = trimmed.find("://") {
        let scheme = &trimmed[..pos];
        if !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            return Err(SecurityError::UrlSchemeProhibited(input.to_string()));
        }
    }

    // 3. UNC path check (forward slashes or backslashes)
    if trimmed.starts_with(r"\\") || trimmed.starts_with("//") {
        return Err(SecurityError::UncPathProhibited(input.to_string()));
    }

    // 4. Windows drive letter check (e.g. "C:foo", "D:\bar", or embedded "c:/")
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(SecurityError::DriveLetterProhibited(input.to_string()));
    }
    if trimmed.contains(":/") || trimmed.contains(r":\") {
        return Err(SecurityError::DriveLetterProhibited(input.to_string()));
    }

    // 5. Absolute path check (Unix root / or Windows root \)
    if trimmed.starts_with('/') || trimmed.starts_with('\\') {
        return Err(SecurityError::AbsolutePathsProhibited(input.to_string()));
    }
    if Path::new(trimmed).is_absolute() {
        return Err(SecurityError::AbsolutePathsProhibited(input.to_string()));
    }

    // Strip safe leading ./ and .\ prefixes
    let mut clean = trimmed;
    while clean.starts_with("./") || clean.starts_with(r".\") {
        clean = &clean[2..];
        clean = clean.trim_start_matches('/').trim_start_matches('\\');
    }

    if clean.is_empty() || clean == "." {
        return Err(SecurityError::NotAFile(PathBuf::from(input)));
    }

    // 6. Component-by-component traversal and depth check
    let mut out = PathBuf::new();
    let mut depth: usize = 0;

    for segment in clean.split(['/', '\\']) {
        let seg = segment.trim();
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(SecurityError::PathTraversal(input.to_string()));
        }
        if seg.contains(':') {
            return Err(SecurityError::DriveLetterProhibited(input.to_string()));
        }
        depth += 1;
        if depth > MAX_PATH_DEPTH {
            return Err(SecurityError::DepthExceeded {
                depth,
                max: MAX_PATH_DEPTH,
            });
        }
        out.push(seg);
    }

    if out.as_os_str().is_empty() {
        return Err(SecurityError::NotAFile(PathBuf::from(input)));
    }

    Ok(out)
}

/// Checks whether a path targets sensitive files, secrets, or critical system resources.
///
/// Blocks:
/// - `.env`, `.env.*`, `*.env`
/// - `.git`, `.git/config`, `.ssh`, `.aws`, `.azure`, `.gcloud`, `.kube`, `.docker`, `.gnupg`
/// - Private keys: `.pem`, `.key`, `.p12`, `.pfx`, `.pkcs12`, `id_rsa*`, `id_ed25519*`
/// - System files: `win.ini`, `system.ini`, `sam`, `system`, `/etc/passwd`, `/etc/shadow`, etc.
///
/// Matches case-insensitively across path components and file names.
pub fn is_sensitive_path<P: AsRef<Path>>(path: P) -> bool {
    let p = path.as_ref();
    let full_str = p.to_string_lossy().to_lowercase().replace('\\', "/");
    let trimmed_full = full_str.trim_start_matches("./");

    // System directories and critical paths
    if trimmed_full.contains("/etc/passwd")
        || trimmed_full.contains("/etc/shadow")
        || trimmed_full.contains("/etc/sudoers")
        || trimmed_full.contains("windows/system32")
        || trimmed_full.contains("system32/config")
        || trimmed_full == "etc/passwd"
        || trimmed_full == "etc/shadow"
        || trimmed_full == "etc/sudoers"
    {
        return true;
    }

    for component in p.components() {
        let comp_str = component.as_os_str().to_string_lossy().to_lowercase();
        let comp_trimmed = comp_str.trim();

        // 1. Environment files
        if comp_trimmed == ".env"
            || comp_trimmed.starts_with(".env.")
            || comp_trimmed.ends_with(".env")
            || comp_trimmed == ".envrc"
            || comp_trimmed.starts_with(".envrc.")
        {
            return true;
        }

        // 2. Sensitive directories
        if comp_trimmed == ".git"
            || comp_trimmed == ".ssh"
            || comp_trimmed == ".aws"
            || comp_trimmed == ".azure"
            || comp_trimmed == ".gcloud"
            || comp_trimmed == ".kube"
            || comp_trimmed == ".docker"
            || comp_trimmed == ".gnupg"
            || comp_trimmed == "secrets"
            || comp_trimmed == ".secrets"
            || comp_trimmed == "credentials"
            || comp_trimmed == ".credentials"
        {
            return true;
        }

        // 3. Sensitive file names
        if comp_trimmed == "win.ini"
            || comp_trimmed == "system.ini"
            || comp_trimmed == "sam"
            || comp_trimmed == "system"
            || comp_trimmed == "passwd"
            || comp_trimmed == "shadow"
            || comp_trimmed == "sudoers"
            || comp_trimmed == "credentials"
            || comp_trimmed == "secrets"
            || comp_trimmed == "secret"
            || comp_trimmed == "service-account.json"
            || comp_trimmed == "service_account.json"
            || comp_trimmed == "master.key"
            || comp_trimmed == "authorized_keys"
            || comp_trimmed == "known_hosts"
            || comp_trimmed == ".npmrc"
            || comp_trimmed == ".pypirc"
            || comp_trimmed == ".netrc"
            || comp_trimmed == ".htpasswd"
        {
            return true;
        }

        // 3b. Secret prefixes
        if comp_trimmed.starts_with("credentials.")
            || comp_trimmed.starts_with("secrets.")
            || comp_trimmed.starts_with("secret.")
            || comp_trimmed.starts_with("service-account.")
            || comp_trimmed.starts_with("service_account.")
        {
            return true;
        }

        // 4. Private keys and SSH identities
        if comp_trimmed.starts_with("id_rsa")
            || comp_trimmed.starts_with("id_ed25519")
            || comp_trimmed.starts_with("id_ecdsa")
            || comp_trimmed.starts_with("id_dsa")
        {
            return true;
        }
    }

    // 5. Key / secret extensions
    if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
        let ext_lower = ext.to_lowercase();
        if ext_lower == "pem"
            || ext_lower == "key"
            || ext_lower == "p12"
            || ext_lower == "pfx"
            || ext_lower == "pkcs12"
            || ext_lower == "kdbx"
            || ext_lower == "der"
            || ext_lower == "crt"
            || ext_lower == "cer"
            || ext_lower == "jks"
            || ext_lower == "keystore"
        {
            return true;
        }
    }

    false
}

/// Validates that a path does not target sensitive files; returns
/// `Err(SecurityError::SensitiveFileProhibited)` if it does.
pub fn validate_not_sensitive<P: AsRef<Path>>(path: P) -> Result<(), SecurityError> {
    if is_sensitive_path(&path) {
        Err(SecurityError::SensitiveFileProhibited(
            path.as_ref().to_string_lossy().to_string(),
        ))
    } else {
        Ok(())
    }
}

/// Validates that the file has an allowed raw extension (case-insensitive).
///
/// Allowed: png, jpg, jpeg, gif, svg, webp, ico, bmp, tiff, pdf, json, md, markdown, txt, csv.
///
/// Returns the matched canonical extension `&'static str` on success,
/// or `Err(SecurityError::ExtensionNotAllowed)` on failure.
pub fn validate_raw_extension<P: AsRef<Path>>(path: P) -> Result<&'static str, SecurityError> {
    let p = path.as_ref();
    let ext = match p.extension().and_then(|s| s.to_str()) {
        Some(e) if !e.is_empty() => e.to_lowercase(),
        _ => {
            return Err(SecurityError::ExtensionNotAllowed {
                extension: String::new(),
                allowed: ALLOWED_RAW_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
            });
        }
    };

    match ext.as_str() {
        "png" => Ok("png"),
        "jpg" => Ok("jpg"),
        "jpeg" => Ok("jpeg"),
        "gif" => Ok("gif"),
        "svg" => Ok("svg"),
        "webp" => Ok("webp"),
        "ico" => Ok("ico"),
        "bmp" => Ok("bmp"),
        "tiff" => Ok("tiff"),
        "pdf" => Ok("pdf"),
        "json" => Ok("json"),
        "md" => Ok("md"),
        "markdown" => Ok("markdown"),
        "txt" => Ok("txt"),
        "csv" => Ok("csv"),
        _ => Err(SecurityError::ExtensionNotAllowed {
            extension: ext,
            allowed: ALLOWED_RAW_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
        }),
    }
}
