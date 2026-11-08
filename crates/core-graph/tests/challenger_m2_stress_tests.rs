//! Empirical Challenger Stress Tests for Milestone M2 (True Dataflow / SSA Taint Tracking)
//!
//! Validates:
//! - Exact variable identifier propagation trace (both display_id and scoped_id)
//! - Neutralization by recognized sanitizers (intval, clean_sql, DOMPurify.sanitize, escapeshellarg)
//! - 0 vulnerability alerts emitted when all paths are sanitized
//! - Mismatched CWE sanitizers fail to neutralize
//! - Branching with unsanitized paths remains vulnerable (conservative Phi join)
//! - Re-tainting after sanitization triggers alert
//! - Double / chained sanitizers recorded properly
//! - Cyclic dataflow graphs terminate cleanly

use core_graph::dataflow::{
    DataflowEdge, DataflowGraph, SinkKind, SourceKind, SsaVar, TaintSink, TaintSource,
    TaintStepKind,
};

#[test]
fn test_challenger_exact_variable_identifier_propagation_trace() {
    let mut dfg = DataflowGraph::new();

    // 5-hop inter-procedural chain across 5 distinct functions
    let v_src = SsaVar::new("$raw_input", 0, "web_entry", 10).with_file("entry.php");
    let v_ctrl = SsaVar::new("$req_param", 1, "controller_action", 25).with_file("controller.php");
    let v_serv = SsaVar::new("$payload", 0, "business_service", 42).with_file("service.php");
    let v_repo = SsaVar::new("$query_frag", 2, "sql_repository", 88).with_file("repo.php");
    let v_sink = SsaVar::new("$final_sql", 0, "db_driver", 105).with_file("driver.php");

    dfg.add_source(
        TaintSource::new(v_src.clone(), SourceKind::HttpQueryParam, "CWE-89")
            .with_description("User search param"),
    );

    // Hop 1: web_entry -> controller_action
    dfg.add_edge(DataflowEdge::new(
        v_src.clone(),
        v_ctrl.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "web_entry".to_string(),
            callee_function: "controller_action".to_string(),
            arg_index: 0,
            param_name: "$req_param".to_string(),
        },
        25,
        false,
        None,
    ));

    // Hop 2: controller_action -> business_service
    dfg.add_edge(DataflowEdge::new(
        v_ctrl.clone(),
        v_serv.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "controller_action".to_string(),
            callee_function: "business_service".to_string(),
            arg_index: 1,
            param_name: "$payload".to_string(),
        },
        42,
        false,
        None,
    ));

    // Hop 3: business_service -> sql_repository
    dfg.add_edge(DataflowEdge::new(
        v_serv.clone(),
        v_repo.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "business_service".to_string(),
            callee_function: "sql_repository".to_string(),
            arg_index: 0,
            param_name: "$query_frag".to_string(),
        },
        88,
        false,
        None,
    ));

    // Hop 4: sql_repository -> db_driver (string concatenation)
    dfg.add_edge(DataflowEdge::new(
        v_repo.clone(),
        v_sink.clone(),
        TaintStepKind::BinaryExpression,
        105,
        false,
        None,
    ));

    dfg.add_sink(
        TaintSink::new(v_sink.clone(), SinkKind::SqlExecution, "CWE-89")
            .with_rule("CWE-89-SQLI-CRITICAL", "CRITICAL")
            .with_description("Direct PDO query execution"),
    );

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1, "Exactly one trace expected");

    let trace = &traces[0];
    assert_eq!(trace.is_vulnerable, true, "Unsanitized flow MUST be vulnerable");
    assert_eq!(trace.is_sanitized, false, "Unsanitized flow MUST NOT be marked sanitized");
    assert_eq!(trace.steps.len(), 4, "Must have exactly 4 steps");

    // EMPIRICAL ASSERTION 1: Exact variable identifiers in order
    let expected_vars = vec![
        "$raw_input#0",
        "$req_param#1",
        "$payload#0",
        "$query_frag#2",
        "$final_sql#0",
    ];
    assert_eq!(trace.traversed_variables(), expected_vars);

    // EMPIRICAL ASSERTION 2: Exact scoped identifiers in order
    let expected_scoped = vec![
        "web_entry::$raw_input#0",
        "controller_action::$req_param#1",
        "business_service::$payload#0",
        "sql_repository::$query_frag#2",
        "db_driver::$final_sql#0",
    ];
    assert_eq!(trace.traversed_scoped_variables(), expected_scoped);

    // EMPIRICAL ASSERTION 3: Active vulnerabilities count MUST be exactly 1
    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].sink.rule_id, "CWE-89-SQLI-CRITICAL");
}

#[test]
fn test_challenger_sanitizer_neutralization_intval() {
    let mut dfg = DataflowGraph::new();

    let v_src = SsaVar::new("user_id", 0, "api_handler", 10);
    let v_clean = SsaVar::new("clean_id", 1, "api_handler", 12);
    let v_query = SsaVar::new("sql_stmt", 0, "api_handler", 14);

    dfg.add_source(TaintSource::new(v_src.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    // Step 1: intval sanitizer
    dfg.add_edge(DataflowEdge::new(
        v_src.clone(),
        v_clean.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "intval".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        12,
        true,
        Some("intval".to_string()),
    ));

    // Step 2: query construction
    dfg.add_edge(DataflowEdge::new(
        v_clean.clone(),
        v_query.clone(),
        TaintStepKind::BinaryExpression,
        14,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v_query.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("SQLI-01", "CRITICAL"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    let trace = &traces[0];
    assert_eq!(trace.is_sanitized, true, "intval MUST neutralize CWE-89 taint");
    assert_eq!(trace.is_vulnerable, false, "Neutralized flow MUST NOT be vulnerable");
    assert!(trace.applied_sanitizers.contains(&"intval".to_string()));

    // EMPIRICAL ASSERTION: 0 vulnerability alerts at Sink!
    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 0, "intval MUST produce 0 vulnerability alerts at the Sink");
}

#[test]
fn test_challenger_sanitizer_neutralization_clean_sql() {
    let mut dfg = DataflowGraph::new();

    let v_src = SsaVar::new("search_term", 0, "search_api", 5);
    let v_clean = SsaVar::new("escaped_term", 1, "search_api", 6);
    let v_sink = SsaVar::new("db_exec", 0, "search_api", 7);

    dfg.add_source(TaintSource::new(v_src.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    dfg.add_edge(DataflowEdge::new(
        v_src.clone(),
        v_clean.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "clean_sql".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        6,
        true,
        Some("clean_sql".to_string()),
    ));

    dfg.add_edge(DataflowEdge::new(
        v_clean.clone(),
        v_sink.clone(),
        TaintStepKind::DirectAssignment,
        7,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v_sink.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("SQLI-02", "CRITICAL"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    let trace = &traces[0];
    assert_eq!(trace.is_sanitized, true);
    assert_eq!(trace.is_vulnerable, false);
    assert!(trace.applied_sanitizers.contains(&"clean_sql".to_string()));

    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 0, "clean_sql MUST produce 0 vulnerability alerts at the Sink");
}

#[test]
fn test_challenger_sanitizer_neutralization_dompurify() {
    let mut dfg = DataflowGraph::new();

    let v_src = SsaVar::new("user_comment", 0, "comment_box", 20);
    let v_clean = SsaVar::new("safe_comment", 1, "comment_box", 22);
    let v_sink = SsaVar::new("dom_element", 0, "comment_box", 24);

    dfg.add_source(TaintSource::new(v_src.clone(), SourceKind::HttpBodyParam, "CWE-79"));

    dfg.add_edge(DataflowEdge::new(
        v_src.clone(),
        v_clean.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "DOMPurify.sanitize".to_string(),
            cwe_targeted: "CWE-79".to_string(),
        },
        22,
        true,
        Some("DOMPurify.sanitize".to_string()),
    ));

    dfg.add_edge(DataflowEdge::new(
        v_clean.clone(),
        v_sink.clone(),
        TaintStepKind::DirectAssignment,
        24,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v_sink.clone(), SinkKind::HtmlRender, "CWE-79")
        .with_rule("XSS-01", "CRITICAL"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    let trace = &traces[0];
    assert_eq!(trace.is_sanitized, true, "DOMPurify.sanitize MUST neutralize CWE-79 taint");
    assert_eq!(trace.is_vulnerable, false);
    assert!(trace.applied_sanitizers.contains(&"DOMPurify.sanitize".to_string()));

    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 0, "DOMPurify.sanitize MUST produce 0 vulnerability alerts at the Sink");
}

#[test]
fn test_challenger_sanitizer_neutralization_escapeshellarg() {
    let mut dfg = DataflowGraph::new();

    let v_src = SsaVar::new("filename", 0, "backup_tool", 30);
    let v_clean = SsaVar::new("escaped_filename", 1, "backup_tool", 31);
    let v_sink = SsaVar::new("cmd_string", 0, "backup_tool", 32);

    dfg.add_source(TaintSource::new(v_src.clone(), SourceKind::HttpQueryParam, "CWE-78"));

    dfg.add_edge(DataflowEdge::new(
        v_src.clone(),
        v_clean.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "escapeshellarg".to_string(),
            cwe_targeted: "CWE-78".to_string(),
        },
        31,
        true,
        Some("escapeshellarg".to_string()),
    ));

    dfg.add_edge(DataflowEdge::new(
        v_clean.clone(),
        v_sink.clone(),
        TaintStepKind::BinaryExpression,
        32,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v_sink.clone(), SinkKind::CommandExecution, "CWE-78")
        .with_rule("CMDI-01", "CRITICAL"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    let trace = &traces[0];
    assert_eq!(trace.is_sanitized, true, "escapeshellarg MUST neutralize CWE-78 taint");
    assert_eq!(trace.is_vulnerable, false);
    assert!(trace.applied_sanitizers.contains(&"escapeshellarg".to_string()));

    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 0, "escapeshellarg MUST produce 0 vulnerability alerts at the Sink");
}

#[test]
fn test_challenger_mismatched_cwe_sanitizer_does_not_neutralize() {
    let mut dfg = DataflowGraph::new();

    // Source is SQL Injection (CWE-89)
    let v_src = SsaVar::new("user_input", 0, "query_handler", 10);
    let v_mid = SsaVar::new("sanitized_val", 1, "query_handler", 11);
    let v_sink = SsaVar::new("sql_call", 0, "query_handler", 12);

    dfg.add_source(TaintSource::new(v_src.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    // INADEQUATE SANITIZER: escapeshellarg is for CWE-78, NOT for CWE-89 SQLi!
    dfg.add_edge(DataflowEdge::new(
        v_src.clone(),
        v_mid.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "escapeshellarg".to_string(),
            cwe_targeted: "CWE-78".to_string(),
        },
        11,
        true,
        Some("escapeshellarg".to_string()),
    ));

    dfg.add_edge(DataflowEdge::new(
        v_mid.clone(),
        v_sink.clone(),
        TaintStepKind::DirectAssignment,
        12,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v_sink.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("MISMATCH-SQLI", "CRITICAL"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    let trace = &traces[0];
    assert_eq!(trace.is_sanitized, false, "escapeshellarg MUST NOT sanitize a SQL injection sink!");
    assert_eq!(trace.is_vulnerable, true);

    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 1, "Alert MUST be emitted when sanitizer does not match sink CWE");
}

#[test]
fn test_challenger_reassignment_with_fresh_taint_triggers_alert() {
    let mut dfg = DataflowGraph::new();

    // Taint source 1
    let v_src1 = SsaVar::new("input_a", 0, "merge_handler", 10);
    // Taint source 2
    let v_src2 = SsaVar::new("input_b", 0, "merge_handler", 11);

    // input_a is sanitized to safe_a#1
    let v_clean1 = SsaVar::new("safe_a", 1, "merge_handler", 12);

    // But then combined: final_var#0 = safe_a#1 . input_b#0 (re-tainted by input_b!)
    let v_combined = SsaVar::new("final_var", 0, "merge_handler", 15);

    dfg.add_source(TaintSource::new(v_src1.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    dfg.add_source(TaintSource::new(v_src2.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    // Edge from input_a to safe_a (sanitized)
    dfg.add_edge(DataflowEdge::new(
        v_src1.clone(),
        v_clean1.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "clean_sql".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        12,
        true,
        Some("clean_sql".to_string()),
    ));
    dfg.add_edge(DataflowEdge::new(
        v_clean1.clone(),
        v_combined.clone(),
        TaintStepKind::BinaryExpression,
        15,
        false,
        None,
    ));

    // Edge from input_b to final_var (raw, unsanitized)
    dfg.add_edge(DataflowEdge::new(
        v_src2.clone(),
        v_combined.clone(),
        TaintStepKind::BinaryExpression,
        15,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v_combined.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("RE-TAINTED-SQLI", "CRITICAL"));

    let traces = dfg.track_dataflow();
    // One trace from src1 (sanitized), one trace from src2 (unsanitized)
    assert_eq!(traces.len(), 2);

    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 1, "Unsanitized input_b MUST trigger an active vulnerability alert at final_var");
    assert_eq!(active[0].source.var.name, "input_b");
}

#[test]
fn test_challenger_nested_multi_sanitizer_chain() {
    let mut dfg = DataflowGraph::new();

    let v0 = SsaVar::new("x", 0, "cleaner", 1);
    let v1 = SsaVar::new("x", 1, "cleaner", 2);
    let v2 = SsaVar::new("x", 2, "cleaner", 3);
    let v_sink = SsaVar::new("query", 0, "cleaner", 4);

    dfg.add_source(TaintSource::new(v0.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    // Step 1: clean_sql
    dfg.add_edge(DataflowEdge::new(
        v0.clone(),
        v1.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "clean_sql".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        2,
        true,
        Some("clean_sql".to_string()),
    ));

    // Step 2: intval
    dfg.add_edge(DataflowEdge::new(
        v1.clone(),
        v2.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "intval".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        3,
        true,
        Some("intval".to_string()),
    ));

    dfg.add_edge(DataflowEdge::new(
        v2.clone(),
        v_sink.clone(),
        TaintStepKind::DirectAssignment,
        4,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v_sink.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("DOUBLE-CLEAN-SQLI", "CRITICAL"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    let trace = &traces[0];

    assert_eq!(trace.is_sanitized, true);
    assert_eq!(trace.is_vulnerable, false);
    assert!(trace.applied_sanitizers.contains(&"clean_sql".to_string()));
    assert!(trace.applied_sanitizers.contains(&"intval".to_string()));

    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 0);
}

#[test]
fn test_challenger_cyclic_dataflow_termination() {
    let mut dfg = DataflowGraph::new();

    let v0 = SsaVar::new("loop_var", 0, "loop_fn", 10);
    let v1 = SsaVar::new("loop_var", 1, "loop_fn", 12);
    let v_sink = SsaVar::new("sink_var", 0, "loop_fn", 20);

    dfg.add_source(TaintSource::new(v0.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    dfg.add_sink(TaintSink::new(v_sink.clone(), SinkKind::SqlExecution, "CWE-89"));

    // Cycle: v0 -> v1 -> v0
    dfg.add_edge(DataflowEdge::new(v0.clone(), v1.clone(), TaintStepKind::DirectAssignment, 11, false, None));
    dfg.add_edge(DataflowEdge::new(v1.clone(), v0.clone(), TaintStepKind::DirectAssignment, 13, false, None));
    // Exit edge: v1 -> v_sink
    dfg.add_edge(DataflowEdge::new(v1.clone(), v_sink.clone(), TaintStepKind::DirectAssignment, 15, false, None));

    // Verify termination without infinite loop
    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].is_vulnerable, true);
}
