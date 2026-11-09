//! Adversarial empirical stress tests for `crates/obsidian-vault/src/confinement.rs`.
//!
//! Evaluates CWE-22 mitigations, Windows drive escapes, UNC paths, null-byte injections,
//! URL protocols, symlink escapes, depth exhaustion, and 10MB file limit defenses.

use obsidian_vault::confinement::{PathGuard, SecurityError, DEFAULT_MAX_FILE_SIZE, MAX_PATH_DEPTH};
use obsidian_vault::types::ObsidianError;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use tempfile::tempdir;

// ============================================================================
// 1. Parent Directory Traversal Stress Tests
// ============================================================================

#[test]
fn test_adversarial_parent_directory_traversals() {
    let vault = tempdir().expect("Failed to create vault tempdir");
    let outside = tempdir().expect("Failed to create outside tempdir");

    // Put a secret outside
    let secret_file = outside.path().join("secret.txt");
    fs::write(&secret_file, "OUTSIDE_CONFIDENTIAL").unwrap();

    let jail = PathGuard::new(vault.path()).expect("Failed to create PathGuard");

    // Attack payloads attempting parent directory traversal
    let traversal_payloads = [
        "../outside.md",
        "../../etc/passwd",
        "../../../etc/shadow",
        "../../../../Windows/System32/cmd.exe",
        "foo/../../bar/../../secret.txt",
        "notes/sub/../../../secret.txt",
        r"..\outside.md",
        r"..\..\Windows\win.ini",
        r"notes\..\..\outside.md",
        r"notes\sub\..\..\..\secret.txt",
        "sub/../outside.md",
        "sub/../../outside.md",
        "a/b/c/../../../../escape.txt",
        "./../../escape.md",
        "notes/./../../escape.md",
    ];

    for payload in &traversal_payloads {
        // 1. validate_lexical_path must reject
        let lex_res = PathGuard::validate_lexical_path(payload);
        assert!(
            matches!(lex_res, Err(SecurityError::PathTraversal(_))),
            "Expected PathTraversal for payload: {payload}, got: {lex_res:?}"
        );

        // 2. sanitize_relative_path must reject
        let san_res = PathGuard::sanitize_relative_path(payload);
        assert!(
            matches!(san_res, Err(SecurityError::PathTraversal(_))),
            "Expected PathTraversal in sanitize for payload: {payload}, got: {san_res:?}"
        );

        // 3. resolve_and_verify must reject and never escape
        let res_res = jail.resolve_and_verify(Path::new(payload));
        assert!(
            res_res.is_err(),
            "Expected error in resolve_and_verify for payload: {payload}, got: {res_res:?}"
        );

        // 4. read_to_string must fail
        let read_res = jail.read_to_string(payload);
        assert!(
            read_res.is_err(),
            "Expected error in read_to_string for payload: {payload}, got: {read_res:?}"
        );

        // 5. is_inside_jail must return false
        assert!(
            !jail.is_inside_jail(Path::new(payload)),
            "is_inside_jail returned true for attack payload: {payload}"
        );
    }
}

#[test]
fn test_adversarial_quad_dots_and_malformed_traversal() {
    let vault = tempdir().expect("Failed to create vault tempdir");
    let jail = PathGuard::new(vault.path()).expect("Failed to create PathGuard");

    // Payloads with quad-dots, triple-dots, semicolons, etc.
    let malformed_payloads = [
        "....//....//file.md",
        ".../.../file.md",
        "..../..../secret.txt",
        r"....\....\secret.txt",
    ];

    for payload in &malformed_payloads {
        // Even if lexical check treats "...." as a normal filename, resolve_and_verify
        // must either reject or keep it strictly inside the vault root (never escape).
        let res = jail.resolve_and_verify(Path::new(payload));
        if let Ok(resolved) = res {
            assert!(
                resolved.starts_with(jail.canonical_root()),
                "Quad dot path resolved outside canonical root: {resolved:?}"
            );
        } else {
            // Expected to fail (NotFound IoError or similar) because no file named "...." exists
            assert!(res.is_err());
        }
    }
}

// ============================================================================
// 2. Windows Drive Letter Escapes
// ============================================================================

#[test]
fn test_adversarial_windows_drive_letter_escapes() {
    let vault = tempdir().expect("Failed to create vault tempdir");
    let jail = PathGuard::new(vault.path()).expect("Failed to create PathGuard");

    let drive_payloads = [
        r"C:\Windows\System32",
        r"C:\Windows\System32\drivers\etc\hosts",
        "c:/windows/system32/cmd.exe",
        r"D:\data\secret.txt",
        "d:/data/secret.txt",
        r"Z:\confidential.md",
        "C:relative_drive_file.txt",
        "D:something.md",
        "sub/c:/test.md",
        r"sub\c:\test.md",
        r"foo/D:\bar",
        "notes/E:/secret.txt",
        r"\\?\C:\Windows\System32",
        r"\\?\D:\secret",
        r"//?/C:/Windows",
    ];

    for payload in &drive_payloads {
        let lex_res = PathGuard::validate_lexical_path(payload);
        assert!(
            lex_res.is_err(),
            "validate_lexical_path failed to reject drive escape: {payload}"
        );
        match lex_res.unwrap_err() {
            SecurityError::DriveLetterProhibited(_)
            | SecurityError::UncPathProhibited(_)
            | SecurityError::InvalidPrefix(_) => {
                // Appropriate security rejection
            }
            other => panic!("Unexpected error variant for drive payload {payload}: {other:?}"),
        }

        // resolve_and_verify must strictly block (cannot jailbreak to Windows system files)
        let res = jail.resolve_and_verify(Path::new(payload));
        assert!(
            res.is_err(),
            "resolve_and_verify allowed Windows drive letter path: {payload}"
        );

        assert!(
            !jail.is_inside_jail(Path::new(payload)),
            "is_inside_jail was true for drive letter escape: {payload}"
        );
    }
}

// ============================================================================
// 3. UNC Network Paths
// ============================================================================

#[test]
fn test_adversarial_unc_network_paths_lexical_rejection() {
    let unc_payloads = [
        r"\\server\share\file.md",
        r"\\192.168.1.1\share\payload.md",
        r"\\127.0.0.1\c$\Windows\win.ini",
        r"\\localhost\share\note.md",
        r"\\attacker.evil.com\exfil\notes.md",
        "//remote/share/file.md",
        "//192.168.1.1/share/stolen.md",
        "//localhost/c$/test.md",
        r"\\?\UNC\server\share\file.md",
        r"\\.\PhysicalDrive0",
        r"\\.\COM1",
        r"\\.\NUL",
    ];

    for payload in &unc_payloads {
        let lex_res = PathGuard::validate_lexical_path(payload);
        assert!(
            matches!(lex_res, Err(SecurityError::UncPathProhibited(_))),
            "Expected UncPathProhibited for payload: {payload}, got: {lex_res:?}"
        );

        let san_res = PathGuard::sanitize_relative_path(payload);
        assert!(
            san_res.is_err(),
            "sanitize_relative_path allowed UNC path: {payload}"
        );
    }
}

#[test]
fn test_adversarial_unc_resolve_and_verify_behavior() {
    let vault = tempdir().expect("Failed to create vault tempdir");
    let jail = PathGuard::new(vault.path()).expect("Failed to create PathGuard");

    // Test a local invalid UNC-like path that fails immediately without remote DNS/SMB timeouts
    // e.g. "//?/invalid/share"
    let local_unc = r"\\localhost\nonexistent_share_xyz\test.md";
    let res = jail.resolve_and_verify(Path::new(local_unc));
    // Verify it is rejected (never allowed inside jail)
    assert!(res.is_err(), "resolve_and_verify allowed UNC path!");
    assert!(!jail.is_inside_jail(Path::new(local_unc)));
}

// ============================================================================
// 4. Null-Byte Injections
// ============================================================================

#[test]
fn test_adversarial_null_byte_injections() {
    let vault = tempdir().expect("Failed to create vault tempdir");
    let jail = PathGuard::new(vault.path()).expect("Failed to create PathGuard");

    let null_payloads = [
        "note.md\0.txt",
        "\0secret.md",
        "docs/sub\0/secret.md",
        "secret.md\0",
        "file.md\0\0\0",
        "safe.md\0/../../etc/passwd",
        "notes/\0/doc.md",
    ];

    for payload in &null_payloads {
        let lex_res = PathGuard::validate_lexical_path(payload);
        assert!(
            matches!(lex_res, Err(SecurityError::NullByteDetected(_))),
            "Expected NullByteDetected in validate_lexical_path for: {payload:?}, got: {lex_res:?}"
        );

        let san_res = PathGuard::sanitize_relative_path(payload);
        assert!(
            matches!(san_res, Err(SecurityError::NullByteDetected(_))),
            "Expected NullByteDetected in sanitize_relative_path for: {payload:?}, got: {san_res:?}"
        );

        let res = jail.resolve_and_verify(Path::new(payload));
        assert!(
            matches!(res, Err(SecurityError::NullByteDetected(_))),
            "Expected NullByteDetected in resolve_and_verify for: {payload:?}, got: {res:?}"
        );

        let read_res = jail.read_to_string(payload);
        assert!(
            matches!(read_res, Err(SecurityError::NullByteDetected(_))),
            "Expected NullByteDetected in read_to_string for: {payload:?}, got: {read_res:?}"
        );

        assert!(!jail.is_inside_jail(Path::new(payload)));
    }
}

// ============================================================================
// 5. URL Schemes and Protocols
// ============================================================================

#[test]
fn test_adversarial_url_protocols() {
    let vault = tempdir().expect("Failed to create vault tempdir");
    let jail = PathGuard::new(vault.path()).expect("Failed to create PathGuard");

    let url_payloads = [
        "file:///etc/passwd",
        "file://C:/Windows/win.ini",
        "file:///C:/Users/secret.txt",
        "http://evil.com/payload.md",
        "https://malicious.org/script.sh",
        "ftp://ftp.server.com/resource",
        "gopher://evil.com/something",
        "custom+scheme://target",
        "git://host/repo.git",
        "ws://echo.websocket.org",
        "file:/etc/passwd",
    ];

    for payload in &url_payloads {
        let lex_res = PathGuard::validate_lexical_path(payload);
        assert!(
            lex_res.is_err(),
            "Expected rejection of URL protocol payload: {payload}"
        );
        match lex_res.unwrap_err() {
            SecurityError::UrlSchemeProhibited(_) | SecurityError::DriveLetterProhibited(_) => {
                // Expected URL or drive prohibited error
            }
            other => panic!("Unexpected error for URL payload {payload}: {other:?}"),
        }

        let san_res = PathGuard::sanitize_relative_path(payload);
        assert!(
            san_res.is_err(),
            "Expected sanitize_relative_path error for URL: {payload}"
        );

        let res = jail.resolve_and_verify(Path::new(payload));
        assert!(res.is_err(), "resolve_and_verify allowed URL: {payload}");
        assert!(!jail.is_inside_jail(Path::new(payload)));
    }
}

// ============================================================================
// 6. Symlink and Junction Escapes
// ============================================================================

#[test]
fn test_adversarial_symlink_escapes_outside_root() {
    let vault = tempdir().expect("Failed to create vault tempdir");
    let outside = tempdir().expect("Failed to create outside tempdir");

    // Target outside vault
    let outside_target = outside.path().join("super_secret.txt");
    fs::write(&outside_target, "CLASSIFIED_TOP_SECRET_DATA").unwrap();

    // Link inside vault pointing outside
    let symlink_in_vault = vault.path().join("escape_link.md");

    #[cfg(unix)]
    let symlink_res = std::os::unix::fs::symlink(&outside_target, &symlink_in_vault);

    #[cfg(windows)]
    let symlink_res = std::os::windows::fs::symlink_file(&outside_target, &symlink_in_vault);

    if symlink_res.is_ok() {
        let jail = PathGuard::new(vault.path()).expect("Failed to create PathGuard");

        // 1. resolve_and_verify must detect symlink escape
        let res = jail.resolve_and_verify("escape_link.md");
        assert!(
            matches!(res, Err(SecurityError::SymlinkEscape { .. })),
            "Expected SymlinkEscape, got: {res:?}"
        );

        // 2. read_to_string must fail with SymlinkEscape
        let read_res = jail.read_to_string("escape_link.md");
        assert!(
            matches!(read_res, Err(SecurityError::SymlinkEscape { .. })),
            "Expected SymlinkEscape in read_to_string, got: {read_res:?}"
        );

        // 3. read_bytes must fail with SymlinkEscape
        let bytes_res = jail.read_bytes("escape_link.md");
        assert!(
            matches!(bytes_res, Err(SecurityError::SymlinkEscape { .. })),
            "Expected SymlinkEscape in read_bytes, got: {bytes_res:?}"
        );

        // 4. open_read must fail
        let open_res = jail.open_read("escape_link.md");
        assert!(
            matches!(open_res, Err(SecurityError::SymlinkEscape { .. })),
            "Expected SymlinkEscape in open_read, got: {open_res:?}"
        );

        assert!(!jail.is_inside_jail("escape_link.md"));
    } else {
        println!(
            "Notice: Symlink creation skipped due to OS permissions (Windows unprivileged mode)"
        );
    }
}

#[test]
fn test_adversarial_symlinks_disabled_policy() {
    let vault = tempdir().expect("Failed to create vault tempdir");

    let real_note = vault.path().join("real_note.md");
    fs::write(&real_note, "# Content").unwrap();

    let link_note = vault.path().join("link_note.md");

    #[cfg(unix)]
    let symlink_res = std::os::unix::fs::symlink(&real_note, &link_note);

    #[cfg(windows)]
    let symlink_res = std::os::windows::fs::symlink_file(&real_note, &link_note);

    if symlink_res.is_ok() {
        // Disallow internal symlinks
        let strict_jail = PathGuard::with_options(vault.path(), DEFAULT_MAX_FILE_SIZE, false).unwrap();
        let res = strict_jail.resolve_and_verify("link_note.md");
        assert!(
            matches!(res, Err(SecurityError::SymlinksDisabled(_))),
            "Expected SymlinksDisabled when symlinks are policy-disabled, got: {res:?}"
        );

        // Allow internal symlinks
        let permissive_jail = PathGuard::with_options(vault.path(), DEFAULT_MAX_FILE_SIZE, true).unwrap();
        let ok_res = permissive_jail.resolve_and_verify("link_note.md");
        assert!(ok_res.is_ok(), "Internal symlink should be allowed when enabled");
    }
}

// ============================================================================
// 7. Resource Exhaustion: 10MB File Limit
// ============================================================================

#[test]
fn test_adversarial_file_size_limits() {
    let vault = tempdir().expect("Failed to create vault tempdir");
    let jail = PathGuard::new(vault.path()).expect("Failed to create PathGuard");

    // 1. File exactly at default 10MB limit (10 * 1024 * 1024)
    let ten_mb = 10 * 1024 * 1024;
    let ten_mb_file = vault.path().join("exact_10mb.md");
    {
        let f = File::create(&ten_mb_file).unwrap();
        // Write sparse or buffered
        f.set_len(ten_mb).unwrap();
    }

    // 10MB exactly should be accepted (<= 10MB)
    assert!(jail.resolve_and_verify("exact_10mb.md").is_ok());

    // 2. File exceeding limit by 1 byte
    let over_file = vault.path().join("ten_mb_plus_one.md");
    {
        let f = File::create(&over_file).unwrap();
        f.set_len(ten_mb + 1).unwrap();
    }

    let read_res = jail.read_to_string("ten_mb_plus_one.md");
    assert!(
        matches!(
            read_res,
            Err(SecurityError::FileTooLarge {
                size,
                max_size,
                ..
            }) if size == ten_mb + 1 && max_size == DEFAULT_MAX_FILE_SIZE
        ),
        "Expected FileTooLarge for 10MB + 1 byte file, got: {read_res:?}"
    );

    let bytes_res = jail.read_bytes("ten_mb_plus_one.md");
    assert!(
        matches!(
            bytes_res,
            Err(SecurityError::FileTooLarge {
                size,
                max_size,
                ..
            }) if size == ten_mb + 1 && max_size == DEFAULT_MAX_FILE_SIZE
        ),
        "Expected FileTooLarge in read_bytes for 10MB + 1 byte file, got: {bytes_res:?}"
    );

    // 3. Much larger file (25 MB)
    let large_file = vault.path().join("large_25mb.bin");
    {
        let f = File::create(&large_file).unwrap();
        f.set_len(25 * 1024 * 1024).unwrap();
    }
    assert!(matches!(
        jail.read_to_string("large_25mb.bin"),
        Err(SecurityError::FileTooLarge { .. })
    ));

    // 4. Custom smaller limit (1024 bytes)
    let custom_jail = PathGuard::with_options(vault.path(), 1024, true).unwrap();
    let small_file = vault.path().join("small_2048.txt");
    fs::write(&small_file, vec![b'x'; 2048]).unwrap();

    let custom_res = custom_jail.read_to_string("small_2048.txt");
    assert!(
        matches!(
            custom_res,
            Err(SecurityError::FileTooLarge {
                size: 2048,
                max_size: 1024,
                ..
            })
        ),
        "Expected FileTooLarge with custom 1024 byte limit, got: {custom_res:?}"
    );
}

// ============================================================================
// 8. Depth Exhaustion and Structural Attacks
// ============================================================================

#[test]
fn test_adversarial_depth_exhaustion() {
    let mut deep_path = String::new();
    for i in 0..=MAX_PATH_DEPTH {
        deep_path.push_str(&format!("d{i}/"));
    }
    deep_path.push_str("final.md");

    let lex_res = PathGuard::validate_lexical_path(&deep_path);
    assert!(
        matches!(
            lex_res,
            Err(SecurityError::DepthExceeded { depth, max })
            if depth > max && max == MAX_PATH_DEPTH
        ),
        "Expected DepthExceeded for deeply nested path, got: {lex_res:?}"
    );
}

#[test]
fn test_adversarial_not_a_file_violation() {
    let vault = tempdir().expect("Failed to create vault tempdir");
    let subfolder = vault.path().join("notes_directory");
    fs::create_dir_all(&subfolder).unwrap();

    let jail = PathGuard::new(vault.path()).expect("Failed to create PathGuard");

    // Reading a directory as a file must fail with NotAFile
    let open_res = jail.open_read("notes_directory");
    assert!(
        matches!(open_res, Err(SecurityError::NotAFile(_))),
        "Expected NotAFile in open_read for directory, got: {open_res:?}"
    );

    let read_res = jail.read_to_string("notes_directory");
    assert!(
        matches!(read_res, Err(SecurityError::NotAFile(_))),
        "Expected NotAFile in read_to_string for directory, got: {read_res:?}"
    );

    let bytes_res = jail.read_bytes("notes_directory");
    assert!(
        matches!(bytes_res, Err(SecurityError::NotAFile(_))),
        "Expected NotAFile in read_bytes for directory, got: {bytes_res:?}"
    );
}

#[test]
fn test_adversarial_root_jail_validation() {
    let temp = tempdir().expect("tempdir");

    // 1. Non-existent root directory
    let non_existent = temp.path().join("does_not_exist_xyz");
    let err_root = PathGuard::new(&non_existent);
    assert!(
        matches!(err_root, Err(SecurityError::RootCanonicalizationFailed { .. })),
        "Expected RootCanonicalizationFailed for missing path, got: {err_root:?}"
    );

    // 2. File as root instead of directory
    let file_root = temp.path().join("file_not_dir.txt");
    fs::write(&file_root, "not a directory").unwrap();
    let err_file = PathGuard::new(&file_root);
    assert!(
        matches!(err_file, Err(SecurityError::RootNotADirectory(_))),
        "Expected RootNotADirectory for file root, got: {err_file:?}"
    );
}

// ============================================================================
// 9. Error Mapping to ObsidianError
// ============================================================================

#[test]
fn test_security_error_conversion_to_obsidian_error() {
    let p_trav = SecurityError::PathTraversal("../../escape.md".to_string());
    let obs_trav: ObsidianError = p_trav.into();
    assert!(
        matches!(obs_trav, ObsidianError::PathTraversal(_)),
        "Expected ObsidianError::PathTraversal"
    );

    let s_esc = SecurityError::SymlinkEscape {
        symlink_path: PathBuf::from("link.md"),
        resolved_path: PathBuf::from("/etc/passwd"),
        root: PathBuf::from("/vault"),
    };
    let obs_esc: ObsidianError = s_esc.into();
    assert!(
        matches!(obs_esc, ObsidianError::SymlinkEscape(_)),
        "Expected ObsidianError::SymlinkEscape"
    );

    let f_large = SecurityError::FileTooLarge {
        path: PathBuf::from("big.bin"),
        size: 15_000_000,
        max_size: 10_000_000,
    };
    let obs_large: ObsidianError = f_large.into();
    assert!(
        matches!(obs_large, ObsidianError::FileTooLarge { size_bytes: 15_000_000, max_bytes: 10_000_000, .. }),
        "Expected ObsidianError::FileTooLarge"
    );

    let null_byte = SecurityError::NullByteDetected("evil\0.md".to_string());
    let obs_sec: ObsidianError = null_byte.into();
    assert!(
        matches!(obs_sec, ObsidianError::Security(_)),
        "Expected ObsidianError::Security for null byte"
    );
}
