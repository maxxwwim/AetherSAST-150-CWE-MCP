use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Errors arising from path confinement, lexical validation, or file access violations.
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Null byte detected in path: {0:?}")]
    NullByteDetected(String),

    #[error("Path traversal attempt detected ('..'): {0}")]
    PathTraversal(String),

    #[error("Absolute paths are prohibited: {0}")]
    AbsolutePathsProhibited(String),

    #[error("UNC network path prohibited: {0}")]
    UncPathProhibited(String),

    #[error("Drive letter prohibited in relative path: {0}")]
    DriveLetterProhibited(String),

    #[error("URL scheme prohibited in path: {0}")]
    UrlSchemeProhibited(String),

    #[error("Invalid or unrecognized path prefix: {0}")]
    InvalidPrefix(String),

    #[error("Access to sensitive or secret file prohibited: {0}")]
    SensitiveFileProhibited(String),

    #[error("File extension '{extension}' is not permitted (allowed: {allowed:?})")]
    ExtensionNotAllowed {
        extension: String,
        allowed: Vec<String>,
    },

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
