//! Strict filesystem confinement jail, lexical path validation, symlink defense,
//! and read-only file access for Obsidian vault processing.
//!
//! Enforces CWE-22 mitigations:
//! 1. Rejection of null bytes (`\0`).
//! 2. Rejection of parent directory traversal (`..`).
//! 3. Rejection of UNC paths (`\\server\share`, `//server/share`).
//! 4. Rejection of drive letters (`C:`) in relative paths.
//! 5. Rejection of URL schemes (`http://`, `file://`).
//! 6. Symlink escape defense (canonical path must strictly reside within canonical root).
//! 7. Read-only file access guarantee with maximum file size limits (DoS mitigation).

use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf, Prefix};
use thiserror::Error;

/// Default maximum file size permitted for reading (10 MB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Default maximum path depth to prevent deep nesting traversal issues.
pub const MAX_PATH_DEPTH: usize = 32;

/// Errors arising from path confinement, lexical validation, or file access violations.
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Null byte detected in path: {0:?}")]
    NullByteDetected(String),

    #[error("Path traversal attempt detected ('..'): {0}")]
    PathTraversal(String),

    #[error("UNC network path prohibited: {0}")]
    UncPathProhibited(String),

    #[error("Drive letter prohibited in relative path: {0}")]
    DriveLetterProhibited(String),

    #[error("URL scheme prohibited in path: {0}")]
    UrlSchemeProhibited(String),

    #[error("Invalid or unrecognized path prefix: {0}")]
    InvalidPrefix(String),

    #[error("Root directory canonicalization failed for '{root}': {source}")]
    RootCanonicalizationFailed {
        root: PathBuf,
        source: io::Error,
    },

    #[error("Root path is not a directory: {0}")]
    RootNotADirectory(PathBuf),

    #[error("Target path '{path}' escapes jail root '{root}' (canonical: '{canonical}')")]
    PathEscapesRoot {
        path: PathBuf,
        canonical: PathBuf,
        root: PathBuf,
    },

    #[error("Symlink '{symlink_path}' escapes jail root to '{resolved_path}' (root: '{root}')")]
    SymlinkEscape {
        symlink_path: PathBuf,
        resolved_path: PathBuf,
        root: PathBuf,
    },

    #[error("Symlinks are disabled by security policy: {0}")]
    SymlinksDisabled(PathBuf),

    #[error("Target is not a regular file: {0}")]
    NotAFile(PathBuf),

    #[error("File '{path}' size ({size} bytes) exceeds maximum limit ({max_size} bytes)")]
    FileTooLarge {
        path: PathBuf,
        size: u64,
        max_size: u64,
    },

    #[error("Path recursion depth exceeds maximum allowed ({depth} > {max})")]
    DepthExceeded {
        depth: usize,
        max: usize,
    },

    #[error("I/O error for path '{path}': {source}")]
    IoError {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Security jail enforcing that all filesystem operations are strictly confined
/// to a designated root directory.
#[derive(Debug, Clone)]
pub struct PathGuard {
    /// Canonicalized absolute root path of the jail.
    canonical_root: PathBuf,
    /// Maximum allowed file size in bytes for reading into memory.
    max_file_size: u64,
    /// Whether internal symlinks (resolving inside the root) are permitted.
    allow_internal_symlinks: bool,
}

/// Type alias for `PathGuard` providing naming compatibility with `TargetJail`.
pub type TargetJail = PathGuard;

impl PathGuard {
    /// Creates a new `PathGuard` rooted at the specified directory with default limits.
    ///
    /// The root path is immediately canonicalized and validated as an existing directory.
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, SecurityError> {
        Self::with_options(root, DEFAULT_MAX_FILE_SIZE, true)
    }

    /// Creates a new `PathGuard` with custom limits.
    pub fn with_options<P: AsRef<Path>>(
        root: P,
        max_file_size: u64,
        allow_internal_symlinks: bool,
    ) -> Result<Self, SecurityError> {
        let root_ref = root.as_ref();
        let canonical_root = fs::canonicalize(root_ref).map_err(|e| {
            SecurityError::RootCanonicalizationFailed {
                root: root_ref.to_path_buf(),
                source: e,
            }
        })?;

        if !canonical_root.is_dir() {
            return Err(SecurityError::RootNotADirectory(canonical_root));
        }

        Ok(Self {
            canonical_root,
            max_file_size,
            allow_internal_symlinks,
        })
    }

    /// Returns a reference to the canonicalized root directory.
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

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
        Self::validate_lexical_path(trimmed)?;

        // Strip any leading slashes or dots
        let clean = trimmed
            .trim_start_matches('/')
            .trim_start_matches('\\')
            .trim_start_matches("./");

        if clean.is_empty() {
            return Ok(PathBuf::new());
        }

        // Re-validate clean slice
        Self::validate_lexical_path(clean)?;

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

    /// Resolves and strictly verifies that a target path resides within the jail.
    ///
    /// Handles both relative paths (joined to `canonical_root`) and absolute paths.
    /// Validates symlinks and confirms that the ultimate canonical path begins with
    /// `canonical_root`.
    pub fn resolve_and_verify<P: AsRef<Path>>(&self, candidate: P) -> Result<PathBuf, SecurityError> {
        let candidate_ref = candidate.as_ref();
        let path_str = candidate_ref.to_string_lossy();

        // 1. Basic lexical safety: null bytes check
        if path_str.as_bytes().contains(&0) || path_str.contains('\0') {
            return Err(SecurityError::NullByteDetected(path_str.to_string()));
        }

        // 2. Traversal check (..)
        for comp in candidate_ref.components() {
            if comp == Component::ParentDir {
                return Err(SecurityError::PathTraversal(path_str.to_string()));
            }
        }

        // 3. Resolve to candidate full path
        let full_path = if candidate_ref.is_absolute() {
            candidate_ref.to_path_buf()
        } else {
            Self::validate_lexical_path(&path_str)?;
            self.canonical_root.join(candidate_ref)
        };

        // 4. Symlink metadata check
        let is_symlink = match fs::symlink_metadata(&full_path) {
            Ok(meta) => meta.file_type().is_symlink(),
            Err(e) => {
                return Err(SecurityError::IoError {
                    path: full_path,
                    source: e,
                });
            }
        };

        if is_symlink && !self.allow_internal_symlinks {
            return Err(SecurityError::SymlinksDisabled(full_path));
        }

        // 5. Canonicalize full path (resolves all symlinks, '.' and '..')
        let canonical_target = fs::canonicalize(&full_path).map_err(|e| {
            SecurityError::IoError {
                path: full_path.clone(),
                source: e,
            }
        })?;

        // 6. Strict root containment verification
        if !canonical_target.starts_with(&self.canonical_root) {
            if is_symlink {
                return Err(SecurityError::SymlinkEscape {
                    symlink_path: full_path,
                    resolved_path: canonical_target,
                    root: self.canonical_root.clone(),
                });
            } else {
                return Err(SecurityError::PathEscapesRoot {
                    path: full_path,
                    canonical: canonical_target,
                    root: self.canonical_root.clone(),
                });
            }
        }

        Ok(canonical_target)
    }

    /// Checks whether an existing path resides strictly inside the jail.
    pub fn is_inside_jail<P: AsRef<Path>>(&self, candidate: P) -> bool {
        self.resolve_and_verify(candidate).is_ok()
    }

    /// Safely opens a file in read-only mode within the target jail.
    pub fn open_read<P: AsRef<Path>>(&self, path: P) -> Result<File, SecurityError> {
        let verified_path = self.resolve_and_verify(path.as_ref())?;

        let metadata = fs::metadata(&verified_path).map_err(|e| SecurityError::IoError {
            path: verified_path.clone(),
            source: e,
        })?;

        if !metadata.is_file() {
            return Err(SecurityError::NotAFile(verified_path));
        }

        File::open(&verified_path).map_err(|e| SecurityError::IoError {
            path: verified_path,
            source: e,
        })
    }

    /// Safely reads the entire content of a file as a String, enforcing
    /// maximum file size limits (DoS prevention).
    pub fn read_to_string<P: AsRef<Path>>(&self, path: P) -> Result<String, SecurityError> {
        let verified_path = self.resolve_and_verify(path.as_ref())?;

        let metadata = fs::metadata(&verified_path).map_err(|e| SecurityError::IoError {
            path: verified_path.clone(),
            source: e,
        })?;

        if !metadata.is_file() {
            return Err(SecurityError::NotAFile(verified_path));
        }

        if metadata.len() > self.max_file_size {
            return Err(SecurityError::FileTooLarge {
                path: verified_path,
                size: metadata.len(),
                max_size: self.max_file_size,
            });
        }

        fs::read_to_string(&verified_path).map_err(|e| SecurityError::IoError {
            path: verified_path,
            source: e,
        })
    }

    /// Safely reads the binary contents of an attachment file (e.g. images, audio),
    /// enforcing maximum file size limits.
    pub fn read_bytes<P: AsRef<Path>>(&self, path: P) -> Result<Vec<u8>, SecurityError> {
        let verified_path = self.resolve_and_verify(path.as_ref())?;

        let metadata = fs::metadata(&verified_path).map_err(|e| SecurityError::IoError {
            path: verified_path.clone(),
            source: e,
        })?;

        if !metadata.is_file() {
            return Err(SecurityError::NotAFile(verified_path));
        }

        if metadata.len() > self.max_file_size {
            return Err(SecurityError::FileTooLarge {
                path: verified_path,
                size: metadata.len(),
                max_size: self.max_file_size,
            });
        }

        fs::read(&verified_path).map_err(|e| SecurityError::IoError {
            path: verified_path,
            source: e,
        })
    }

    /// Computes a clean, forward-slash normalized relative path from the jail root.
    pub fn secure_relative_path<P: AsRef<Path>>(&self, path: P) -> Result<String, SecurityError> {
        let verified_canonical = self.resolve_and_verify(path)?;
        let rel = verified_canonical
            .strip_prefix(&self.canonical_root)
            .map_err(|_| SecurityError::PathEscapesRoot {
                path: verified_canonical.clone(),
                canonical: verified_canonical.clone(),
                root: self.canonical_root.clone(),
            })?;

        let rel_str = rel.to_string_lossy().replace('\\', "/");
        Ok(rel_str)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_jail_creation_valid_and_invalid() {
        let dir = tempdir().unwrap();
        let jail = PathGuard::new(dir.path());
        assert!(jail.is_ok(), "PathGuard must succeed on valid directory");

        let file_path = dir.path().join("not_a_dir.txt");
        File::create(&file_path).unwrap();
        let jail_err = PathGuard::new(&file_path);
        assert!(
            matches!(jail_err, Err(SecurityError::RootNotADirectory(_))),
            "PathGuard must reject non-directory root"
        );
    }

    #[test]
    fn test_jail_read_valid_nested_file() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("notes").join("sub");
        fs::create_dir_all(&sub).unwrap();

        let note = sub.join("test.md");
        let mut f = File::create(&note).unwrap();
        f.write_all(b"# Hello Obsidian").unwrap();

        let jail = PathGuard::new(dir.path()).unwrap();
        let content = jail.read_to_string("notes/sub/test.md").unwrap();
        assert_eq!(content, "# Hello Obsidian");

        let rel = jail.secure_relative_path("notes/sub/test.md").unwrap();
        assert_eq!(rel, "notes/sub/test.md");
    }

    #[test]
    fn test_jail_lexical_null_byte_rejection() {
        assert!(matches!(
            PathGuard::validate_lexical_path("note.md\0.txt"),
            Err(SecurityError::NullByteDetected(_))
        ));
        assert!(matches!(
            PathGuard::sanitize_relative_path("docs/secret\0.md"),
            Err(SecurityError::NullByteDetected(_))
        ));
    }

    #[test]
    fn test_jail_lexical_parent_traversal_rejection() {
        assert!(matches!(
            PathGuard::validate_lexical_path("../outside.md"),
            Err(SecurityError::PathTraversal(_))
        ));
        assert!(matches!(
            PathGuard::validate_lexical_path("sub/../../outside.md"),
            Err(SecurityError::PathTraversal(_))
        ));
        assert!(matches!(
            PathGuard::validate_lexical_path(r"sub\..\..\outside.md"),
            Err(SecurityError::PathTraversal(_))
        ));
        assert!(matches!(
            PathGuard::sanitize_relative_path("../evil.md"),
            Err(SecurityError::PathTraversal(_))
        ));
    }

    #[test]
    fn test_jail_lexical_unc_path_rejection() {
        assert!(matches!(
            PathGuard::validate_lexical_path(r"\\192.168.1.1\share\stolen.md"),
            Err(SecurityError::UncPathProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_lexical_path("//remote-server/share/file.md"),
            Err(SecurityError::UncPathProhibited(_))
        ));
    }

    #[test]
    fn test_jail_lexical_drive_letter_rejection() {
        assert!(matches!(
            PathGuard::validate_lexical_path("C:/Windows/win.ini"),
            Err(SecurityError::DriveLetterProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_lexical_path(r"D:\Data\note.md"),
            Err(SecurityError::DriveLetterProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_lexical_path("sub/c:/test.md"),
            Err(SecurityError::DriveLetterProhibited(_))
        ));
    }

    #[test]
    fn test_jail_lexical_url_scheme_rejection() {
        assert!(matches!(
            PathGuard::validate_lexical_path("http://evil.com/note.md"),
            Err(SecurityError::UrlSchemeProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_lexical_path("file:///etc/passwd"),
            Err(SecurityError::UrlSchemeProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_lexical_path("https://vault.com/note"),
            Err(SecurityError::UrlSchemeProhibited(_))
        ));
    }

    #[test]
    fn test_jail_canonical_escape_prevention() {
        let vault_dir = tempdir().unwrap();
        let outside_dir = tempdir().unwrap();

        let secret = outside_dir.path().join("secret.txt");
        File::create(&secret).unwrap();

        let jail = PathGuard::new(vault_dir.path()).unwrap();
        let result = jail.resolve_and_verify(&secret);
        assert!(
            matches!(result, Err(SecurityError::PathEscapesRoot { .. })),
            "Must reject path residing outside root"
        );
    }

    #[test]
    fn test_jail_symlink_escape_prevention() {
        let vault_dir = tempdir().unwrap();
        let outside_dir = tempdir().unwrap();

        let outside_secret = outside_dir.path().join("outside_secret.md");
        fs::write(&outside_secret, "CONFIDENTIAL").unwrap();

        let link_inside = vault_dir.path().join("leak_link.md");

        #[cfg(unix)]
        let symlink_created = std::os::unix::fs::symlink(&outside_secret, &link_inside).is_ok();

        #[cfg(windows)]
        let symlink_created = std::os::windows::fs::symlink_file(&outside_secret, &link_inside).is_ok();

        if symlink_created {
            let jail = PathGuard::new(vault_dir.path()).unwrap();
            let result = jail.read_to_string("leak_link.md");
            assert!(
                matches!(result, Err(SecurityError::SymlinkEscape { .. })),
                "Must detect and block symlinks escaping the vault jail"
            );
        }
    }

    #[test]
    fn test_jail_internal_symlink_support() {
        let vault_dir = tempdir().unwrap();
        let real_file = vault_dir.path().join("real.md");
        fs::write(&real_file, "REAL CONTENT").unwrap();

        let sym_file = vault_dir.path().join("alias.md");

        #[cfg(unix)]
        let symlink_created = std::os::unix::fs::symlink(&real_file, &sym_file).is_ok();

        #[cfg(windows)]
        let symlink_created = std::os::windows::fs::symlink_file(&real_file, &sym_file).is_ok();

        if symlink_created {
            let jail = PathGuard::new(vault_dir.path()).unwrap();
            let content = jail.read_to_string("alias.md").unwrap();
            assert_eq!(content, "REAL CONTENT");
        }
    }

    #[test]
    fn test_jail_max_file_size_exceeded() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("large.md");
        let payload = vec![b'a'; 1024]; // 1 KB
        fs::write(&file_path, &payload).unwrap();

        let jail = PathGuard::with_options(dir.path(), 512, true).unwrap();
        let result = jail.read_to_string("large.md");
        assert!(
            matches!(result, Err(SecurityError::FileTooLarge { size: 1024, max_size: 512, .. })),
            "Must reject file exceeding max size"
        );
    }

    #[test]
    fn test_jail_not_a_file_error() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("subfolder");
        fs::create_dir_all(&sub).unwrap();

        let jail = PathGuard::new(dir.path()).unwrap();
        let result = jail.open_read("subfolder");
        assert!(
            matches!(result, Err(SecurityError::NotAFile(_))),
            "Opening directory as file must fail with NotAFile"
        );
    }

    #[test]
    fn test_jail_sanitize_relative_path_edge_cases() {
        assert_eq!(
            PathGuard::sanitize_relative_path("notes/sub/doc.md").unwrap(),
            PathBuf::from("notes").join("sub").join("doc.md")
        );
        assert_eq!(
            PathGuard::sanitize_relative_path("/notes/doc.md").unwrap(),
            PathBuf::from("notes").join("doc.md")
        );
        assert_eq!(
            PathGuard::sanitize_relative_path(r"\notes\doc.md").unwrap(),
            PathBuf::from("notes").join("doc.md")
        );
        assert_eq!(
            PathGuard::sanitize_relative_path("./notes/doc.md").unwrap(),
            PathBuf::from("notes").join("doc.md")
        );
    }
}
