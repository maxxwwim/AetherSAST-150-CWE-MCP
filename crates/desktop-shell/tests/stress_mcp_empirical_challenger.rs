//! Empirical Stress Tests and Adversarial Oracles for AetherScope MCP Server & JSON-RPC
//! Agent: teamwork_challenger_obs_m2_2 (Empirical Challenger Archetype)
//! Scope:
//!   1. Complete tools/list verification: 10 tools, 4 capability hints (root & annotations)
//!   2. Adversarial stress tests: aetherscope_switch_view_mode, aetherscope_get_graph_summary, aetherscope_get_active_target
//!   3. True offline fallback resilience when Axum server is unreachable (closed port)
//!   4. JSON-RPC protocol edge cases, fuzzing, and malformed payload recovery
//!   5. Empirical bug oracles documenting confirmed defects

#![recursion_limit = "512"]

#[path = "../src/mcp.rs"]
mod mcp;

use mcp::{handle_mcp_request, send_http_request, JsonRpcRequest};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

// RAII helper for temporary test directories
struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), unique_id));
        fs::create_dir_all(&path).expect("Failed to create temporary test directory");
        Self { path }
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// =========================================================================
// SECTION 1: MCP tools/list Comprehensive Verification (All 10 tools & 4 hints)
// =========================================================================

#[tokio::test]
async fn test_empirical_tools_list_all_10_tools_and_4_hints() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("challenger-tools-list-001")),
        method: "tools/list".to_string(),
        params: None,
    };

    // Use an offline port to ensure tools/list does not depend on server connectivity
    let resp = handle_mcp_request(req, 59999, ".").await.expect("tools/list response must exist");
    assert_eq!(resp.jsonrpc, "2.0");
    assert_eq!(resp.id, Some(json!("challenger-tools-list-001")));
    assert!(resp.error.is_none(), "tools/list should never return an error");

    let result = resp.result.expect("result field must be present");
    let tools = result["tools"].as_array().expect("tools must be an array");

        // Exactly 10 registered tools (curated high-impact suite)
    assert_eq!(tools.len(), 10, "MCP server must expose exactly 10 registered tools");

    // Expected tools and their hint truth table:
    // (name, readOnlyHint, destructiveHint, idempotentHint, openWorldHint)
    let expected_hints = [
        ("aetherscope_get_graph_summary", true, false, true, false),
        ("aetherscope_get_active_target", true, false, true, false),
        ("aetherscope_search_symbols", true, false, true, false),
        ("aetherscope_switch_view_mode", false, false, true, false),
        ("aetherscope_manage_tasks", false, false, false, false),
        ("aetherscope_verify_patch", true, false, true, false),
        ("aetherscope_chat", false, false, false, false),
        ("aetherscope_manage_plugins", false, false, true, false),
        ("aetherscope_teleport_camera", true, false, true, false),
        ("aetherscope_scan_project", true, false, true, false),
    ];

    for (name, expected_ro, expected_dest, expected_idemp, expected_ow) in expected_hints {
        let tool = tools.iter().find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("Required tool '{}' missing from tools/list", name));

        // 1. Description non-empty
        let desc = tool["description"].as_str().expect("description must be a string");
        assert!(!desc.trim().is_empty(), "Description for '{}' must not be empty", name);

        // 2. Top-level capability hints verification
        assert_eq!(tool["readOnlyHint"].as_bool(), Some(expected_ro),
            "Top-level readOnlyHint on '{}' expected {}", name, expected_ro);
        assert_eq!(tool["destructiveHint"].as_bool(), Some(expected_dest),
            "Top-level destructiveHint on '{}' expected {}", name, expected_dest);
        assert_eq!(tool["idempotentHint"].as_bool(), Some(expected_idemp),
            "Top-level idempotentHint on '{}' expected {}", name, expected_idemp);
        assert_eq!(tool["openWorldHint"].as_bool(), Some(expected_ow),
            "Top-level openWorldHint on '{}' expected {}", name, expected_ow);

        // 3. Annotations object verification
        let ann = &tool["annotations"];
        assert!(ann.is_object(), "Annotations must be an object on '{}'", name);
        assert_eq!(ann["readOnlyHint"].as_bool(), Some(expected_ro),
            "Annotations readOnlyHint on '{}' must match top-level", name);
        assert_eq!(ann["destructiveHint"].as_bool(), Some(expected_dest),
            "Annotations destructiveHint on '{}' must match top-level", name);
        assert_eq!(ann["idempotentHint"].as_bool(), Some(expected_idemp),
            "Annotations idempotentHint on '{}' must match top-level", name);
        assert_eq!(ann["openWorldHint"].as_bool(), Some(expected_ow),
            "Annotations openWorldHint on '{}' must match top-level", name);

        // 4. Schema contract verification
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object", "inputSchema type on '{}' must be 'object'", name);
        assert!(schema["properties"].is_object(), "inputSchema.properties on '{}' must be an object", name);
        assert_eq!(schema["additionalProperties"], false, "additionalProperties on '{}' must be false", name);
    }
}

// =========================================================================
// SECTION 2: Adversarial Stress Test — aetherscope_switch_view_mode
// =========================================================================

#[tokio::test]
async fn test_empirical_switch_view_mode_valid_modes() {
    let fixture = TempDirGuard::new("obsidian_switch_valid");
    fs::create_dir_all(fixture.path.join(".obsidian")).unwrap();
    fs::write(fixture.path.join("Index.md"), "# Index\nWelcome to vault.").unwrap();

    let path_str = fixture.path.to_str().unwrap();

    // Test case insensitive & trimmed mode values
    let test_cases = [
        "code",
        "vault",
        "CODE",
        "VAULT",
        "  code  ",
        "  vault  ",
        "Code",
        "Vault",
    ];

    for mode in test_cases {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!("switch-valid")),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_switch_view_mode",
                "arguments": {
                    "mode": mode,
                    "path": path_str
                }
            })),
        };

        let resp = handle_mcp_request(req, 59999, path_str).await.expect("response");
        let res = resp.result.expect("result");
        assert_eq!(res["isError"], false, "Valid mode '{}' should not return isError=true", mode);

        let content = res["content"].as_array().expect("content array");
        assert!(!content.is_empty());
        let text = content[0]["text"].as_str().expect("text");
        let lower_norm = mode.trim().to_lowercase();
        assert!(text.contains(&lower_norm), "Response must mention target mode '{}'", lower_norm);
    }
}

#[tokio::test]
async fn test_empirical_switch_view_mode_invalid_inputs_rejection() {
    let adversarial_modes = [
        "",                     // Empty string
        "    ",                 // Whitespace only
        "notes",                // Note: "notes" is schema enum violation (schema defines ["code", "vault"])
        "invalid",              // Random unknown string
        "3d_vision",            // Unsupported mode
        "../../etc/passwd",     // Path traversal attempt in mode
        "\0nullbyte",           // Null byte injection
        "code\nmalicious",      // Newline injection
        "SELECT * FROM views",  // SQL injection pattern
    ];

    for bad_mode in adversarial_modes {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!("switch-invalid")),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_switch_view_mode",
                "arguments": {
                    "mode": bad_mode
                }
            })),
        };

        let resp = handle_mcp_request(req, 59999, ".").await.expect("response");
        let res = resp.result.expect("result");
        assert_eq!(res["isError"], true, "Invalid mode '{}' must return isError=true", bad_mode);

        let text = res["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("Erreur") || text.contains("doit être"),
            "Error message must explain valid options for '{}'", bad_mode);
    }
}

#[tokio::test]
async fn test_empirical_switch_view_mode_type_mismatch_and_missing_params() {
    let malformed_arguments = vec![
        json!({}),                                    // Missing mode completely
        json!({ "mode": 12345 }),                     // Integer instead of string
        json!({ "mode": true }),                      // Boolean instead of string
        json!({ "mode": ["code"] }),                  // Array instead of string
        json!({ "mode": { "sub": "vault" } }),        // Object instead of string
        json!({ "mode": null }),                      // Null mode
    ];

    for args in malformed_arguments {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!("switch-type-mismatch")),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_switch_view_mode",
                "arguments": args
            })),
        };

        let resp = handle_mcp_request(req, 59999, ".").await.expect("response");
        let res = resp.result.expect("result");
        assert_eq!(res["isError"], true, "Malformed arguments {:?} must return isError=true", args);
    }
}

#[tokio::test]
async fn test_empirical_switch_view_mode_rapid_swapping_stress() {
    let fixture = TempDirGuard::new("obsidian_rapid_switch");
    fs::create_dir_all(fixture.path.join(".obsidian")).unwrap();
    fs::write(fixture.path.join("NoteA.md"), "# Note A\n[[NoteB]]").unwrap();
    fs::write(fixture.path.join("NoteB.md"), "# Note B\n[[NoteA]]").unwrap();

    let path_str = fixture.path.to_str().unwrap();

    // Rapidly toggle between code and vault 6 times in sequence (fast bounded test)
    for i in 0..6 {
        let mode = if i % 2 == 0 { "code" } else { "vault" };
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(i)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_switch_view_mode",
                "arguments": {
                    "mode": mode,
                    "path": path_str
                }
            })),
        };

        let resp = handle_mcp_request(req, 59999, path_str).await.expect("response");
        let res = resp.result.expect("result");
        assert_eq!(res["isError"], false);
    }
}

// =========================================================================
// SECTION 3: Adversarial Stress Test — aetherscope_get_graph_summary
// =========================================================================

#[tokio::test]
async fn test_empirical_graph_summary_mixed_project_classification() {
    let fixture = TempDirGuard::new("graph_summary_mixed");
    // Code component
    fs::create_dir_all(fixture.path.join("src")).unwrap();
    fs::write(fixture.path.join("Cargo.toml"), "[package]\nname = \"mixed-proj\"\nversion = \"0.1.0\"\n").unwrap();
    fs::write(fixture.path.join("src/lib.rs"), "pub fn compute() -> i32 { 42 }\n").unwrap();

    // Vault component
    fs::create_dir_all(fixture.path.join(".obsidian")).unwrap();
    fs::create_dir_all(fixture.path.join("docs")).unwrap();
    fs::write(fixture.path.join("docs/Architecture.md"), "# Architecture\nSee [[Guide]] for setup.\n#kb/mixed\n").unwrap();
    fs::write(fixture.path.join("docs/Guide.md"), "# Guide\nSetup instructions.\n").unwrap();

    let path_str = fixture.path.to_str().unwrap();

    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("summary-mixed")),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "aetherscope_get_graph_summary",
            "arguments": {
                "path": path_str,
                "rescan": true,
                "include_tasks": true
            }
        })),
    };

    let resp = handle_mcp_request(req, 59999, path_str).await.expect("response");
    let res = resp.result.expect("result");
    assert_eq!(res["isError"], false);

    let text = res["content"][0]["text"].as_str().expect("text");
    assert!(text.contains("Mixed"), "Summary must identify mixed project");
    assert!(text.contains("code") && text.contains("vault"), "Summary must show supported views");
}

#[tokio::test]
async fn test_empirical_graph_summary_adversarial_paths_and_filters() {
    // 1. Non-existent path
    let req_nonexistent = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("summary-nonexistent")),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "aetherscope_get_graph_summary",
            "arguments": {
                "path": "c:/non_existent_folder_xyz_987654321/deep/nested",
                "rescan": true
            }
        })),
    };
    let resp = handle_mcp_request(req_nonexistent, 59999, ".").await.expect("response");
    let res = resp.result.expect("result");
    assert_eq!(res["isError"], false);

    // 2. Adversarial severity filter inputs
    for sev in &["critical", "high", "all", "unknown_severity", "SELECT *"] {
        let req_sev = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!("summary-sev")),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_get_graph_summary",
                "arguments": {
                    "path": ".",
                    "severity": sev
                }
            })),
        };
        let resp_sev = handle_mcp_request(req_sev, 59999, ".").await.expect("response");
        assert_eq!(resp_sev.result.expect("result")["isError"], false, "Severity filter '{}' should not crash", sev);
    }
}

// =========================================================================
// SECTION 4: Adversarial Stress Test — aetherscope_get_active_target
// =========================================================================

#[tokio::test]
async fn test_empirical_active_target_missing_and_adversarial_symbols() {
    let fixture = TempDirGuard::new("active_target_adv");
    fs::create_dir_all(fixture.path.join(".obsidian")).unwrap();
    fs::write(fixture.path.join("Valid.md"), "# Valid\nContent.").unwrap();
    let path_str = fixture.path.to_str().unwrap();

    // 1. Missing symbol_id
    let req_missing = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("target-missing")),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "aetherscope_get_active_target",
            "arguments": {
                "path": path_str
            }
        })),
    };
    let resp = handle_mcp_request(req_missing, 59999, path_str).await.expect("response");
    assert_eq!(resp.result.expect("result")["isError"], true);

    // 2. Empty symbol_id
    let req_empty = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("target-empty")),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "aetherscope_get_active_target",
            "arguments": {
                "symbol_id": "   ",
                "path": path_str
            }
        })),
    };
    let resp = handle_mcp_request(req_empty, 59999, path_str).await.expect("response");
    assert_eq!(resp.result.expect("result")["isError"], true);

    // 3. Completely non-existent symbol
    let req_nonexistent = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("target-nonexistent")),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "aetherscope_get_active_target",
            "arguments": {
                "symbol_id": "TotallyNonExistentSymbolInThisProject_XYZ_999",
                "path": path_str
            }
        })),
    };
    let resp = handle_mcp_request(req_nonexistent, 59999, path_str).await.expect("response");
    let res = resp.result.expect("result");
    assert_eq!(res["isError"], true, "Non-existent symbol must return isError=true");
    let text = res["content"][0]["text"].as_str().expect("text");
    assert!(text.contains("introuvable") || text.contains("⚠️") || text.contains("aucun"));

    // 4. Boundary max_depth values (0, 1, 5, 100)
    for depth in &[0, 1, 5, 100] {
        let req_depth = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!("target-depth")),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_get_active_target",
                "arguments": {
                    "symbol_id": "Valid",
                    "path": path_str,
                    "max_depth": depth
                }
            })),
        };
        let resp = handle_mcp_request(req_depth, 59999, path_str).await.expect("response");
        assert_eq!(resp.result.expect("result")["isError"], false, "max_depth {} should not panic", depth);
    }
}

// =========================================================================
// SECTION 5: Offline Fallback Verification (Axum server unreachable)
// =========================================================================

#[tokio::test]
async fn test_empirical_offline_fallback_closed_ports_never_hang_or_crash() {
    let closed_ports = [59101, 59102];

    for port in closed_ports {
        assert!(!mcp::check_server_listening(port), "Port {} should be closed for offline test", port);

        // 1. switch_view_mode offline fallback
        let req_switch = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!("offline-switch")),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_switch_view_mode",
                "arguments": {
                    "mode": "vault",
                    "path": "."
                }
            })),
        };
        let resp_switch = handle_mcp_request(req_switch, port, ".").await.expect("response");
        let res_switch = resp_switch.result.expect("result");
        assert_eq!(res_switch["isError"], false);
        let text_switch = res_switch["content"][0]["text"].as_str().expect("text");
        assert!(text_switch.contains("Mode hors-ligne / Autonome"),
            "Expected offline fallback indicator in switch_view_mode response on port {}", port);

        // 2. get_graph_summary offline fallback
        let req_summary = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!("offline-summary")),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_get_graph_summary",
                "arguments": {
                    "path": ".",
                    "include_tasks": false
                }
            })),
        };
        let resp_summary = handle_mcp_request(req_summary, port, ".").await.expect("response");
        let res_summary = resp_summary.result.expect("result");
        assert_eq!(res_summary["isError"], false);
        let text_summary = res_summary["content"][0]["text"].as_str().expect("text");
        assert!(text_summary.contains("Synthèse Globale") || text_summary.contains("Type de Projet"),
            "Expected graph summary response in offline mode on port {}", port);

        // 3. search_symbols offline fallback
        let req_search = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!("offline-search")),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "aetherscope_search_symbols",
                "arguments": {
                    "query": "mcp",
                    "limit": 5
                }
            })),
        };
        let resp_search = handle_mcp_request(req_search, port, ".").await.expect("response");
        let res_search = resp_search.result.expect("result");
        assert_eq!(res_search["isError"], false);
    }
}

// =========================================================================
// SECTION 6: JSON-RPC Protocol Edge Cases & Robustness
// =========================================================================

#[tokio::test]
async fn test_empirical_jsonrpc_protocol_compliance() {
    // 1. Initialize method returns server capabilities and name
    let req_init = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "initialize".to_string(),
        params: None,
    };
    let resp_init = handle_mcp_request(req_init, 59999, ".").await.expect("init response");
    assert_eq!(resp_init.jsonrpc, "2.0");
    assert_eq!(resp_init.id, Some(json!(1)));
    let server_info = &resp_init.result.expect("result")["serverInfo"];
    assert_eq!(server_info["name"], "aetherscope-mcp");

    // 2. Ping method returns empty result
    let req_ping = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("ping-id")),
        method: "ping".to_string(),
        params: None,
    };
    let resp_ping = handle_mcp_request(req_ping, 59999, ".").await.expect("ping response");
    assert_eq!(resp_ping.jsonrpc, "2.0");
    assert_eq!(resp_ping.result, Some(json!({})));

    // 3. notifications/initialized returns None (no response according to JSON-RPC 2.0 notification semantics)
    let req_notif = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: None,
        method: "notifications/initialized".to_string(),
        params: None,
    };
    let resp_notif = handle_mcp_request(req_notif, 59999, ".").await;
    assert!(resp_notif.is_none(), "Notifications must not produce a response");

    // 4. Unknown tool call
    let req_unknown_tool = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(999)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "non_existent_tool_name_xyz",
            "arguments": {}
        })),
    };
    let resp_unknown = handle_mcp_request(req_unknown_tool, 59999, ".").await.expect("response");
    let res = resp_unknown.result.expect("result");
    assert_eq!(res["isError"], true, "Unknown tool call must return isError=true");

    // 5. Variety of ID types (null, integer, float, string)
    let id_variations = vec![
        None,
        Some(json!(12345)),
        Some(json!("custom-string-id")),
        Some(json!(98.76)),
    ];
    for test_id in id_variations {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: test_id.clone(),
            method: "ping".to_string(),
            params: None,
        };
        let resp = handle_mcp_request(req, 59999, ".").await.expect("response");
        assert_eq!(resp.id, test_id);
    }
}

// =========================================================================
// SECTION 7: EMPIRICAL DEFECT DEMONSTRATIONS (BUG ORACLES)
// =========================================================================

/// BUG ORACLE 1 (Remediated): Verifies that format_graph_summary correctly counts
/// ghost notes and attachments separately from Markdown notes.
#[tokio::test]
async fn test_defect_oracle_ghost_notes_and_attachments_miscounted_as_notes() {
    let fixture = TempDirGuard::new("defect_ghost_summary");
    fs::create_dir_all(fixture.path.join(".obsidian")).unwrap();
    // 1 note that references an unresolved link (ghost note) and an image embed (attachment)
    fs::write(
        fixture.path.join("Index.md"),
        "# Index\nRefers to [[UnresolvedDanglingTarget]] and ![[diagram.png]].\n",
    ).unwrap();
    fs::write(fixture.path.join("diagram.png"), b"\x89PNG\r\n\x1a\n").unwrap();

    let path_str = fixture.path.to_str().unwrap();

    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("defect-oracle-1")),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "aetherscope_get_graph_summary",
            "arguments": {
                "path": path_str,
                "rescan": true
            }
        })),
    };

    let resp = handle_mcp_request(req, 59999, path_str).await.expect("response");
    let res = resp.result.expect("result");
    let text = res["content"][0]["text"].as_str().expect("text");

    println!("Remediated Oracle 1 Output:\n{}", text);
    assert!(
        text.contains("Notes Markdown : 1"),
        "Notes count should be 1 (real note only), got: {}", text
    );
    assert!(
        text.contains("Notes fantômes : 1 cible(s) non résolue(s)"),
        "Ghost notes count should be 1, got: {}", text
    );
    assert!(
        text.contains("1 fichiers joints"),
        "Attachments count should be 1, got: {}", text
    );
}

/// BUG ORACLE 2 (Remediated): Verifies that offline_active_target_fallback resolves
/// a note in a subdirectory whether queried with or without .md extension.
#[tokio::test]
async fn test_defect_oracle_subdirectory_note_with_extension_resolution_failure() {
    let fixture = TempDirGuard::new("defect_target_sub");
    fs::create_dir_all(fixture.path.join(".obsidian")).unwrap();
    fs::create_dir_all(fixture.path.join("docs")).unwrap();
    fs::write(fixture.path.join("docs/Specification.md"), "# Specification\nContent here.\n").unwrap();

    let path_str = fixture.path.to_str().unwrap();

    // 1. Without extension ("Specification"): resolves successfully
    let req_stem = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("test-stem")),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "aetherscope_get_active_target",
            "arguments": {
                "symbol_id": "Specification",
                "path": path_str
            }
        })),
    };
    let resp_stem = handle_mcp_request(req_stem, 59999, path_str).await.expect("stem response");
    assert_eq!(resp_stem.result.expect("result")["isError"], false, "Stem resolution should work");

    // 2. With extension ("Specification.md"): resolves successfully after remediation
    let req_ext = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("test-ext")),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "aetherscope_get_active_target",
            "arguments": {
                "symbol_id": "Specification.md",
                "path": path_str
            }
        })),
    };
    let resp_ext = handle_mcp_request(req_ext, 59999, path_str).await.expect("ext response");
    let res_ext = resp_ext.result.expect("result");

    assert_eq!(res_ext["isError"], false,
        "Subdirectory note with extension 'Specification.md' must resolve successfully");
    let text = res_ext["content"][0]["text"].as_str().expect("text");
    assert!(text.contains("Specification"), "Response should contain note name 'Specification'");
    assert!(!text.contains("introuvable"), "Response should not report note as introuvable");
}

/// BUG ORACLE 3 (Remediated): Verifies that send_http_request rejects HTTP error status codes (400, 422, 500)
/// as Err, preventing callers from falsely reporting success.
#[tokio::test]
async fn test_defect_oracle_send_http_request_swallows_http_error_status() {
    use std::net::TcpListener;

    // Spin up a mock HTTP server on an ephemeral port that always returns HTTP 422 Unprocessable Entity
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();

    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let response = "HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\nContent-Length: 76\r\nConnection: close\r\n\r\n{\"status\":\"error\",\"message\":\"Mode vault non disponible pour un projet PureCode\"}";
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Write);
        }
    });

    // Small delay to ensure listener thread is parked in accept()
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Send HTTP request to the mock server
    let res = send_http_request(port, "POST", "/api/view_mode", Some(&json!({ "mode": "vault" }))).await;

    match res {
        Ok(val) => {
            panic!("Expected Err on HTTP 422, but got Ok: {:?}", val);
        }
        Err(e) => {
            assert!(e.contains("422"), "Error message should contain HTTP status 422: {}", e);
            assert!(e.contains("Mode vault non disponible"), "Error message should contain server error text: {}", e);
            println!("Remediated Oracle 3: send_http_request correctly returned Err on HTTP 422: {}", e);
        }
    }
}

/// BUG ORACLE 4 (Remediated): Verifies that when the Axum server returns 422/400 (e.g. ModeNotSupported),
/// aetherscope_switch_view_mode returns isError=true and reports the rejection to the agent.
#[tokio::test]
async fn test_defect_oracle_switch_view_mode_falsely_reports_success_on_server_error() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();

    tokio::task::spawn_blocking(move || {
        // Serve 2 requests (telemetry + view_mode)
        for _ in 0..2 {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let response = "HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\nContent-Length: 68\r\nConnection: close\r\n\r\n{\"status\":\"error\",\"message\":\"Mode vault non disponible pour PureCode\"}";
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Write);
            }
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("defect-oracle-4")),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "aetherscope_switch_view_mode",
            "arguments": {
                "mode": "vault",
                "path": "."
            }
        })),
    };

    let resp = handle_mcp_request(req, port, ".").await.expect("response");
    let res = resp.result.expect("result");
    let text = res["content"][0]["text"].as_str().expect("text");
    println!("Remediated Oracle 4 Output:\n{}", text);

    assert_eq!(res["isError"], true, "isError must be TRUE when server returns 422 rejection");
    assert!(!text.contains("basculé avec succès"), "Tool must not claim successful switch on server error");
    assert!(text.contains("⚠️") || text.contains("Échec") || text.contains("Mode vault non disponible"),
        "Output should indicate failure, got: {}", text);
}


