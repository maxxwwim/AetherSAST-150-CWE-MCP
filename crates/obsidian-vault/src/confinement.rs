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
use std::path::{Component, Path, PathBuf};

pub use crate::error::SecurityError;
pub use crate::lexical::{ALLOWED_RAW_EXTENSIONS, MAX_PATH_DEPTH};

/// Default maximum file size permitted for reading (10 MB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

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
    pub fn validate_lexical_path(path_str: &str) -> Result<(), SecurityError> {
        crate::lexical::validate_lexical_path(path_str)
    }

    /// Sanitizes a relative path string extracted from markdown (e.g. wikilink target).
    pub fn sanitize_relative_path(raw_path: &str) -> Result<PathBuf, SecurityError> {
        crate::lexical::sanitize_relative_path(raw_path)
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

    /// Strictly validates untrusted client path strings without touching the filesystem.
    pub fn validate_client_relative_path(input: &str) -> Result<PathBuf, SecurityError> {
        crate::lexical::validate_client_relative_path(input)
    }

    /// Checks whether a path targets sensitive files, secrets, or critical system resources.
    pub fn is_sensitive_path<P: AsRef<Path>>(path: P) -> bool {
        crate::lexical::is_sensitive_path(path)
    }

    /// Validates that a path does not target sensitive files; returns
    /// `Err(SecurityError::SensitiveFileProhibited)` if it does.
    pub fn validate_not_sensitive<P: AsRef<Path>>(path: P) -> Result<(), SecurityError> {
        crate::lexical::validate_not_sensitive(path)
    }

    /// Validates that the file has an allowed raw extension (case-insensitive).
    pub fn validate_raw_extension<P: AsRef<Path>>(path: P) -> Result<&'static str, SecurityError> {
        crate::lexical::validate_raw_extension(path)
    }

    /// Resolves and strictly verifies a prospective write target within `canonical_root`.
    ///
    /// Validates the path lexically and ensures it does not target sensitive files.
    /// For new files, ascends to the nearest existing ancestor directory, canonicalizes it,
    /// and verifies that it resides strictly within `canonical_root`.
    /// If the target file already exists, verifies that it is not an escaping symlink.
    pub fn resolve_write_target<P: AsRef<Path>>(&self, candidate_rel: P) -> Result<PathBuf, SecurityError> {
        let path_str = candidate_rel.as_ref().to_string_lossy();
        let clean_rel = Self::validate_client_relative_path(&path_str)?;
        Self::validate_not_sensitive(&clean_rel)?;

        if clean_rel.as_os_str().is_empty() {
            return Err(SecurityError::NotAFile(self.canonical_root.clone()));
        }

        let full_target = self.canonical_root.join(&clean_rel);

        // 1. If target already exists, verify it directly
        if full_target.exists() || fs::symlink_metadata(&full_target).is_ok() {
            let is_symlink = match fs::symlink_metadata(&full_target) {
                Ok(m) => m.file_type().is_symlink(),
                Err(_) => false,
            };

            if is_symlink && !self.allow_internal_symlinks {
                return Err(SecurityError::SymlinksDisabled(full_target));
            }

            let canonical_target = fs::canonicalize(&full_target).map_err(|e| SecurityError::IoError {
                path: full_target.clone(),
                source: e,
            })?;

            if !canonical_target.starts_with(&self.canonical_root) {
                if is_symlink {
                    return Err(SecurityError::SymlinkEscape {
                        symlink_path: full_target,
                        resolved_path: canonical_target,
                        root: self.canonical_root.clone(),
                    });
                } else {
                    return Err(SecurityError::PathEscapesRoot {
                        path: full_target,
                        canonical: canonical_target,
                        root: self.canonical_root.clone(),
                    });
                }
            }

            return Ok(canonical_target);
        }

        // 2. Target does not exist yet. Locate nearest existing ancestor directory.
        let mut ancestor = full_target.parent();
        let mut existing_ancestor = None;
        let mut non_existing_parts = Vec::new();

        while let Some(dir) = ancestor {
            if dir.exists() {
                existing_ancestor = Some(dir);
                break;
            }
            if let Some(name) = dir.file_name() {
                non_existing_parts.push(name.to_os_string());
            }
            ancestor = dir.parent();
        }

        let existing_dir = existing_ancestor.unwrap_or(&self.canonical_root);

        let is_ancestor_symlink = match fs::symlink_metadata(existing_dir) {
            Ok(m) => m.file_type().is_symlink(),
            Err(_) => false,
        };

        let canonical_ancestor = fs::canonicalize(existing_dir).map_err(|e| SecurityError::IoError {
            path: existing_dir.to_path_buf(),
            source: e,
        })?;

        if !canonical_ancestor.starts_with(&self.canonical_root) {
            if is_ancestor_symlink {
                return Err(SecurityError::SymlinkEscape {
                    symlink_path: existing_dir.to_path_buf(),
                    resolved_path: canonical_ancestor,
                    root: self.canonical_root.clone(),
                });
            } else {
                return Err(SecurityError::PathEscapesRoot {
                    path: full_target.clone(),
                    canonical: canonical_ancestor,
                    root: self.canonical_root.clone(),
                });
            }
        }

        // Assemble resolved safe target path
        let mut resolved = canonical_ancestor;
        non_existing_parts.reverse();
        for part in non_existing_parts {
            resolved.push(part);
        }
        if let Some(file_name) = full_target.file_name() {
            resolved.push(file_name);
        }

        if !resolved.starts_with(&self.canonical_root) {
            return Err(SecurityError::PathEscapesRoot {
                path: full_target,
                canonical: resolved,
                root: self.canonical_root.clone(),
            });
        }

        Ok(resolved)
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

    #[test]
    fn test_validate_client_relative_path_comprehensive() {
        // Valid paths
        assert_eq!(
            PathGuard::validate_client_relative_path("README.md").unwrap(),
            PathBuf::from("README.md")
        );
        assert_eq!(
            PathGuard::validate_client_relative_path("./README.md").unwrap(),
            PathBuf::from("README.md")
        );
        assert_eq!(
            PathGuard::validate_client_relative_path(r".\README.md").unwrap(),
            PathBuf::from("README.md")
        );
        assert_eq!(
            PathGuard::validate_client_relative_path("src/lib.rs").unwrap(),
            PathBuf::from("src").join("lib.rs")
        );
        assert_eq!(
            PathGuard::validate_client_relative_path(r"src\lib.rs").unwrap(),
            PathBuf::from("src").join("lib.rs")
        );
        assert_eq!(
            PathGuard::validate_client_relative_path(r"src/sub\module.rs").unwrap(),
            PathBuf::from("src").join("sub").join("module.rs")
        );

        // Lexical rejections
        assert!(matches!(
            PathGuard::validate_client_relative_path(""),
            Err(SecurityError::PathTraversal(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("   "),
            Err(SecurityError::PathTraversal(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("."),
            Err(SecurityError::NotAFile(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("./"),
            Err(SecurityError::NotAFile(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("note.md\0.txt"),
            Err(SecurityError::NullByteDetected(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("http://evil.com/note.md"),
            Err(SecurityError::UrlSchemeProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("file:///etc/passwd"),
            Err(SecurityError::UrlSchemeProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path(r"\\evil.com\share"),
            Err(SecurityError::UncPathProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("//server/share/file.txt"),
            Err(SecurityError::UncPathProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path(r"\\?\C:\Windows\win.ini"),
            Err(SecurityError::UncPathProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("/etc/passwd"),
            Err(SecurityError::AbsolutePathsProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path(r"\Windows\win.ini"),
            Err(SecurityError::AbsolutePathsProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("C:/Windows/win.ini"),
            Err(SecurityError::DriveLetterProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("C:relative.txt"),
            Err(SecurityError::DriveLetterProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("notes/c:/test.md"),
            Err(SecurityError::DriveLetterProhibited(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("../../outside.md"),
            Err(SecurityError::PathTraversal(_))
        ));
        assert!(matches!(
            PathGuard::validate_client_relative_path("sub/../../outside.md"),
            Err(SecurityError::PathTraversal(_))
        ));

        // Depth limits: 32 normal components allowed, 33 rejected
        let depth_32 = (0..32).map(|i| format!("d{i}")).collect::<Vec<_>>().join("/");
        assert!(PathGuard::validate_client_relative_path(&depth_32).is_ok());

        let depth_33 = (0..33).map(|i| format!("d{i}")).collect::<Vec<_>>().join("/");
        assert!(matches!(
            PathGuard::validate_client_relative_path(&depth_33),
            Err(SecurityError::DepthExceeded { .. })
        ));
    }

    #[test]
    fn test_sensitive_file_detection() {
        // Sensitive targets
        let sensitive = [
            ".env",
            ".env.local",
            ".env.production",
            "sub/.env",
            "config/app.env",
            ".ENV",
            ".git/config",
            ".git/HEAD",
            ".git",
            ".ssh/id_rsa",
            ".ssh/authorized_keys",
            "id_rsa",
            "id_rsa.pub",
            "id_ed25519",
            ".aws/credentials",
            "certs/server.key",
            "certs/privkey.pem",
            "auth/token.p12",
            "auth/key.pfx",
            "vault.kdbx",
            "win.ini",
            "system.ini",
            "sam",
            "passwd",
            "shadow",
            "sudoers",
            "/etc/passwd",
            "/etc/shadow",
            "windows/system32/cmd.exe",
        ];

        for path in &sensitive {
            assert!(
                PathGuard::is_sensitive_path(path),
                "Path '{path}' must be flagged as sensitive"
            );
            assert!(
                matches!(
                    PathGuard::validate_not_sensitive(path),
                    Err(SecurityError::SensitiveFileProhibited(_))
                ),
                "Path '{path}' must return SensitiveFileProhibited"
            );
        }

        // Non-sensitive targets
        let non_sensitive = [
            "README.md",
            "src/lib.rs",
            "assets/logo.png",
            "docs/architecture.md",
            "data/notes.json",
        ];

        for path in &non_sensitive {
            assert!(
                !PathGuard::is_sensitive_path(path),
                "Path '{path}' should NOT be sensitive"
            );
            assert!(PathGuard::validate_not_sensitive(path).is_ok());
        }
    }

    #[test]
    fn test_raw_extension_validation() {
        assert_eq!(PathGuard::validate_raw_extension("photo.png").unwrap(), "png");
        assert_eq!(PathGuard::validate_raw_extension("photo.PNG").unwrap(), "png");
        assert_eq!(PathGuard::validate_raw_extension("image.jpg").unwrap(), "jpg");
        assert_eq!(PathGuard::validate_raw_extension("image.jpeg").unwrap(), "jpeg");
        assert_eq!(PathGuard::validate_raw_extension("icon.ico").unwrap(), "ico");
        assert_eq!(PathGuard::validate_raw_extension("anim.gif").unwrap(), "gif");
        assert_eq!(PathGuard::validate_raw_extension("vector.svg").unwrap(), "svg");
        assert_eq!(PathGuard::validate_raw_extension("doc.pdf").unwrap(), "pdf");
        assert_eq!(PathGuard::validate_raw_extension("data.json").unwrap(), "json");
        assert_eq!(PathGuard::validate_raw_extension("note.md").unwrap(), "md");
        assert_eq!(PathGuard::validate_raw_extension("note.markdown").unwrap(), "markdown");
        assert_eq!(PathGuard::validate_raw_extension("text.txt").unwrap(), "txt");
        assert_eq!(PathGuard::validate_raw_extension("data.csv").unwrap(), "csv");

        // Disallowed extensions
        assert!(matches!(
            PathGuard::validate_raw_extension("program.exe"),
            Err(SecurityError::ExtensionNotAllowed { .. })
        ));
        assert!(matches!(
            PathGuard::validate_raw_extension("script.sh"),
            Err(SecurityError::ExtensionNotAllowed { .. })
        ));
        assert!(matches!(
            PathGuard::validate_raw_extension("source.rs"),
            Err(SecurityError::ExtensionNotAllowed { .. })
        ));
        assert!(matches!(
            PathGuard::validate_raw_extension("LICENSE"),
            Err(SecurityError::ExtensionNotAllowed { .. })
        ));
    }

    #[test]
    fn test_resolve_write_target() {
        let vault = tempdir().unwrap();
        let jail = PathGuard::new(vault.path()).unwrap();

        // 1. New file directly in root
        let target = jail.resolve_write_target("new_doc.md").unwrap();
        assert!(target.starts_with(jail.canonical_root()));
        assert_eq!(target.file_name().unwrap(), "new_doc.md");

        // 2. New file in non-existent nested directory
        let deep_target = jail.resolve_write_target("a/b/c/nested.md").unwrap();
        assert!(deep_target.starts_with(jail.canonical_root()));
        assert_eq!(deep_target.file_name().unwrap(), "nested.md");

        // 3. Existing file write target
        let existing = vault.path().join("existing.txt");
        fs::write(&existing, "hello").unwrap();
        let existing_target = jail.resolve_write_target("existing.txt").unwrap();
        assert!(existing_target.starts_with(jail.canonical_root()));

        // 4. Sensitive file blocked
        assert!(matches!(
            jail.resolve_write_target(".env"),
            Err(SecurityError::SensitiveFileProhibited(_))
        ));
        assert!(matches!(
            jail.resolve_write_target(".git/config"),
            Err(SecurityError::SensitiveFileProhibited(_))
        ));

        // 5. Traversal blocked
        assert!(matches!(
            jail.resolve_write_target("../outside.txt"),
            Err(SecurityError::PathTraversal(_))
        ));
    }
}
