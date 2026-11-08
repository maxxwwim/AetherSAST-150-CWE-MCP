//! E2E Test Suite for Requirement R2: True Dataflow & SSA Taint Tracking Engine
//!
//! Validates:
//! - F4: SSA variable core model (`SsaVar`), Sources, Sinks, and `DataflowGraph`.
//! - F5: Intra-procedural def-use SSA tracking and inter-procedural argument & return value propagation.
//! - F6: Sanitizer neutralization engine preventing alert emission when sanitized,
//!       and producing exact variable identifier traces when unsanitized.
//! - Tier 2 Boundary Cases: cyclic calls termination, branch merge ambiguity, nested sanitizers, disconnected flows.

use core_graph::dataflow::{
    DataflowEdge, DataflowGraph, SanitizerMatchKind, SanitizerRule, SinkKind, SourceKind, SsaVar,
    TaintSink, TaintSource, TaintStepKind,
};

/// Helper to create a standard propagation edge
fn edge(from: SsaVar, to: SsaVar, kind: TaintStepKind, line: usize) -> DataflowEdge {
    DataflowEdge::new(from, to, kind, line, false, None)
}

/// Helper to create a sanitized propagation edge
fn sanitized_edge(from: SsaVar, to: SsaVar, kind: TaintStepKind, line: usize, sanitizer_name: &str) -> DataflowEdge {
    DataflowEdge::new(from, to, kind, line, true, Some(sanitizer_name.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 1: FEATURE COVERAGE — F4: SSA DATAFLOW CORE MODEL
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_f4_tier1_ssa_var_creation_versioning_and_display() {
    let var0 = SsaVar::new("user_input", 0, "api_handler", 12).with_file("src/api.rs");
    assert_eq!(var0.name, "user_input");
    assert_eq!(var0.version, 0);
    assert_eq!(var0.func_scope, "api_handler");
    assert_eq!(var0.line, 12);
    assert_eq!(var0.display_id(), "user_input#0");
    assert_eq!(var0.scoped_id(), "api_handler::user_input#0");

    let var1 = SsaVar::new("user_input", 1, "api_handler", 15);
    assert_eq!(var1.display_id(), "user_input#1");
    assert_ne!(var0, var1, "Different SSA versions must not be equal");

    // Scoped ID with empty scope defaults to display_id
    let global_var = SsaVar::new("GLOBAL_CONF", 0, "", 1);
    assert_eq!(global_var.scoped_id(), "GLOBAL_CONF#0");
}

#[test]
fn test_f4_tier1_taint_source_and_sink_declarations() {
    let src_var = SsaVar::new("query_param", 0, "handle_request", 20);
    let source = TaintSource::new(src_var.clone(), SourceKind::HttpQueryParam, "CWE-89")
        .with_description("Untrusted HTTP GET query parameter");

    assert_eq!(source.var, src_var);
    assert_eq!(source.source_kind, SourceKind::HttpQueryParam);
    assert_eq!(source.cwe, "CWE-89");
    assert_eq!(source.description, "Untrusted HTTP GET query parameter");

    let sink_var = SsaVar::new("raw_sql", 1, "db_execute", 45);
    let sink = TaintSink::new(sink_var.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("RULE-SQLI-01", "CRITICAL")
        .with_description("Direct SQL query execution sink");

    assert_eq!(sink.var, sink_var);
    assert_eq!(sink.sink_kind, SinkKind::SqlExecution);
    assert_eq!(sink.rule_id, "RULE-SQLI-01");
    assert_eq!(sink.severity, "CRITICAL");
}

#[test]
fn test_f4_tier1_dataflow_graph_node_and_edge_registration() {
    let mut dfg = DataflowGraph::new();

    let v0 = SsaVar::new("data", 0, "fn_a", 10);
    let v1 = SsaVar::new("data", 1, "fn_a", 12);

    dfg.add_var(v0.clone());
    dfg.add_var(v1.clone());

    let e = edge(v0.clone(), v1.clone(), TaintStepKind::DirectAssignment, 12);
    dfg.add_edge(e);

    assert_eq!(dfg.nodes.len(), 2);
    assert_eq!(dfg.edges.len(), 1);
}

#[test]
fn test_f4_tier1_multi_path_fan_out_one_source_two_sinks() {
    let mut dfg = DataflowGraph::new();

    let src_var = SsaVar::new("input", 0, "dispatch", 5);
    let sql_var = SsaVar::new("sql_query", 0, "db_handler", 15);
    let cmd_var = SsaVar::new("shell_cmd", 0, "sys_handler", 25);

    dfg.add_source(TaintSource::new(src_var.clone(), SourceKind::HttpBodyParam, "*"));
    dfg.add_sink(TaintSink::new(sql_var.clone(), SinkKind::SqlExecution, "CWE-89"));
    dfg.add_sink(TaintSink::new(cmd_var.clone(), SinkKind::CommandExecution, "CWE-78"));

    // Fan-out: input#0 feeds both sql_query#0 and shell_cmd#0
    dfg.add_edge(edge(src_var.clone(), sql_var.clone(), TaintStepKind::DirectAssignment, 10));
    dfg.add_edge(edge(src_var, cmd_var, TaintStepKind::DirectAssignment, 20));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 2, "Both sinks must have traces originating from the single source");

    let sink_cwes: Vec<String> = traces.iter().map(|t| t.sink.cwe.clone()).collect();
    assert!(sink_cwes.contains(&"CWE-89".to_string()));
    assert!(sink_cwes.contains(&"CWE-78".to_string()));

    for trace in traces {
        assert!(trace.is_vulnerable, "Both paths are unsanitized and must be marked vulnerable");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 1: FEATURE COVERAGE — F5: INTRA & INTER-PROCEDURAL PROPAGATION
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_f5_tier1_intra_procedural_ssa_def_use_propagation() {
    let mut dfg = DataflowGraph::new();

    let v0 = SsaVar::new("payload", 0, "process_data", 10);
    let v1 = SsaVar::new("payload", 1, "process_data", 12);
    let v2 = SsaVar::new("payload", 2, "process_data", 14);

    dfg.add_source(TaintSource::new(v0.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    dfg.add_sink(TaintSink::new(v2.clone(), SinkKind::SqlExecution, "CWE-89"));

    dfg.add_edge(edge(v0.clone(), v1.clone(), TaintStepKind::DirectAssignment, 12));
    dfg.add_edge(edge(v1.clone(), v2.clone(), TaintStepKind::BinaryExpression, 14));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    let trace = &traces[0];

    assert!(!trace.is_sanitized);
    assert!(trace.is_vulnerable);
    assert_eq!(trace.steps.len(), 2);

    let var_seq = trace.traversed_variables();
    assert_eq!(var_seq, vec!["payload#0", "payload#1", "payload#2"]);
}

#[test]
fn test_f5_tier1_inter_procedural_call_argument_and_return_propagation() {
    let mut dfg = DataflowGraph::new();

    // Caller: api_endpoint
    let caller_arg = SsaVar::new("user_id", 0, "api_endpoint", 30);
    // Callee: service_helper
    let callee_param = SsaVar::new("raw_id", 0, "service_helper", 50);
    let callee_res = SsaVar::new("query_str", 0, "service_helper", 55);
    // Caller return assignee
    let caller_sink_var = SsaVar::new("final_sql", 1, "api_endpoint", 32);

    dfg.add_source(TaintSource::new(caller_arg.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    dfg.add_sink(TaintSink::new(caller_sink_var.clone(), SinkKind::SqlExecution, "CWE-89"));

    // 1. Inter-procedural Call Arg Passing
    dfg.add_edge(edge(
        caller_arg.clone(),
        callee_param.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "api_endpoint".to_string(),
            callee_function: "service_helper".to_string(),
            arg_index: 0,
            param_name: "raw_id".to_string(),
        },
        30,
    ));

    // 2. Intra-procedural in Callee
    dfg.add_edge(edge(callee_param.clone(), callee_res.clone(), TaintStepKind::BinaryExpression, 55));

    // 3. Inter-procedural Return Value Passing
    dfg.add_edge(edge(
        callee_res.clone(),
        caller_sink_var.clone(),
        TaintStepKind::CallReturnPassing {
            caller_function: "api_endpoint".to_string(),
            callee_function: "service_helper".to_string(),
        },
        32,
    ));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    let trace = &traces[0];

    assert!(trace.is_vulnerable);
    assert_eq!(trace.steps.len(), 3);

    let scoped_vars = trace.traversed_scoped_variables();
    assert_eq!(
        scoped_vars,
        vec![
            "api_endpoint::user_id#0",
            "service_helper::raw_id#0",
            "service_helper::query_str#0",
            "api_endpoint::final_sql#1",
        ]
    );
}

#[test]
fn test_f5_tier1_multi_hop_inter_procedural_chain() {
    let mut dfg = DataflowGraph::new();

    // 4-hop chain: Form -> Controller -> Service -> Repo
    let v_form = SsaVar::new("email", 0, "ui::signup_form", 10);
    let v_ctrl = SsaVar::new("ctrl_email", 0, "controller::handle_signup", 20);
    let v_serv = SsaVar::new("serv_email", 0, "service::create_user", 30);
    let v_repo = SsaVar::new("sql_query", 0, "repo::insert_user", 40);

    dfg.add_source(TaintSource::new(v_form.clone(), SourceKind::HttpBodyParam, "CWE-89"));
    dfg.add_sink(TaintSink::new(v_repo.clone(), SinkKind::SqlExecution, "CWE-89"));

    dfg.add_edge(edge(v_form.clone(), v_ctrl.clone(), TaintStepKind::DirectAssignment, 20));
    dfg.add_edge(edge(v_ctrl.clone(), v_serv.clone(), TaintStepKind::DirectAssignment, 30));
    dfg.add_edge(edge(v_serv.clone(), v_repo.clone(), TaintStepKind::DirectAssignment, 40));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    assert!(traces[0].is_vulnerable);
    assert_eq!(traces[0].steps.len(), 3);

    let scoped_vars = traces[0].traversed_scoped_variables();
    assert!(scoped_vars.contains(&"ui::signup_form::email#0".to_string()));
    assert!(scoped_vars.contains(&"repo::insert_user::sql_query#0".to_string()));

    let formatted = traces[0].format_trace();
    assert!(formatted.contains("VULNERABLE (Exploitable)"));
    assert!(formatted.contains("email#0"));
    assert!(formatted.contains("sql_query#0"));
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 1: FEATURE COVERAGE — F6: SANITIZER NEUTRALIZATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_f6_tier1_sanitizer_neutralization_prevents_alert_at_sink() {
    let mut dfg = DataflowGraph::new();

    let v0 = SsaVar::new("raw_input", 0, "query_user", 10);
    let v1 = SsaVar::new("clean_input", 1, "query_user", 12);
    let v2 = SsaVar::new("sql_stmt", 0, "query_user", 15);

    dfg.add_source(TaintSource::new(v0.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    dfg.add_sink(TaintSink::new(v2.clone(), SinkKind::SqlExecution, "CWE-89"));

    // Step 1: Sanitizer call (clean_sql)
    dfg.add_edge(sanitized_edge(
        v0.clone(),
        v1.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "clean_sql".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        12,
        "clean_sql",
    ));

    // Step 2: Query construction with sanitized variable
    dfg.add_edge(edge(v1.clone(), v2.clone(), TaintStepKind::BinaryExpression, 15));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1, "Must produce a trace");
    let trace = &traces[0];

    // CRITICAL ACCEPTANCE CRITERION:
    // Passage through sanitizer neutralizes taint and prevents alert at Sink!
    assert!(trace.is_sanitized, "Trace must be flagged is_sanitized == true");
    assert!(!trace.is_vulnerable, "is_vulnerable must be FALSE, preventing alert emission at Sink");
    assert!(trace.applied_sanitizers.contains(&"clean_sql".to_string()));

    let trace_str = trace.format_trace();
    assert!(trace_str.contains("SANITIZED (Neutralized - Safe)"));
    assert!(trace_str.contains("clean_sql"));
}

#[test]
fn test_f6_tier1_cwe_specific_sanitizer_isolation() {
    let mut dfg = DataflowGraph::new();

    let v0 = SsaVar::new("input", 0, "search", 10);
    let v1 = SsaVar::new("html_escaped", 1, "search", 12);
    let v2 = SsaVar::new("sql_query", 0, "search", 15);

    dfg.add_source(TaintSource::new(v0.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    // SQL Sink (CWE-89)
    dfg.add_sink(TaintSink::new(v2.clone(), SinkKind::SqlExecution, "CWE-89"));

    // HTML sanitizer (CWE-79) applied to variable that reaches a SQL sink (CWE-89)!
    dfg.add_edge(sanitized_edge(
        v0.clone(),
        v1.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "htmlspecialchars".to_string(),
            cwe_targeted: "CWE-79".to_string(), // Only neutralizes XSS!
        },
        12,
        "htmlspecialchars",
    ));

    dfg.add_edge(edge(v1.clone(), v2.clone(), TaintStepKind::BinaryExpression, 15));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    let trace = &traces[0];

    // HTML escaping does NOT protect against SQL injection!
    assert!(!trace.is_sanitized, "htmlspecialchars must NOT sanitize a CWE-89 SQL injection sink");
    assert!(trace.is_vulnerable, "Alert must fire because vulnerability is NOT neutralized for SQLi");
}

#[test]
fn test_f6_tier1_universal_sanitizer_neutralizes_all_cwes() {
    let mut dfg = DataflowGraph::new();

    let v0 = SsaVar::new("raw", 0, "universal_guard", 10);
    let v1 = SsaVar::new("clean", 1, "universal_guard", 12);
    let v2 = SsaVar::new("sink_var", 0, "universal_guard", 15);

    dfg.add_source(TaintSource::new(v0.clone(), SourceKind::HttpQueryParam, "CWE-78"));
    dfg.add_sink(TaintSink::new(v2.clone(), SinkKind::CommandExecution, "CWE-78"));

    // Register a universal sanitizer
    dfg.add_sanitizer(SanitizerRule::new_all("deep_sanitize", SanitizerMatchKind::ExactName));

    dfg.add_edge(sanitized_edge(v0.clone(), v1.clone(), TaintStepKind::DirectAssignment, 12, "deep_sanitize"));
    dfg.add_edge(edge(v1.clone(), v2.clone(), TaintStepKind::DirectAssignment, 15));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    assert!(traces[0].is_sanitized);
    assert!(!traces[0].is_vulnerable);
}

// ─────────────────────────────────────────────────────────────────────────────
// TIER 2: BOUNDARY & CORNER CASES
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_r2_tier2_cyclic_recursive_call_termination() {
    let mut dfg = DataflowGraph::new();

    let v0 = SsaVar::new("x", 0, "rec_fn", 10);
    let v1 = SsaVar::new("y", 0, "rec_fn", 15);
    let sink_v = SsaVar::new("target", 0, "rec_fn", 20);

    dfg.add_source(TaintSource::new(v0.clone(), SourceKind::FunctionArgument, "CWE-89"));
    dfg.add_sink(TaintSink::new(sink_v.clone(), SinkKind::SqlExecution, "CWE-89"));

    // Cycle: v0 -> v1 -> v0
    dfg.add_edge(edge(v0.clone(), v1.clone(), TaintStepKind::DirectAssignment, 12));
    dfg.add_edge(edge(v1.clone(), v0.clone(), TaintStepKind::DirectAssignment, 14));
    // Exit edge from cycle to sink: v1 -> sink_v
    dfg.add_edge(edge(v1.clone(), sink_v.clone(), TaintStepKind::DirectAssignment, 18));

    // Must terminate without hanging or overflowing recursion stack
    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    assert!(traces[0].is_vulnerable);
}

#[test]
fn test_r2_tier2_branch_merge_with_one_sanitized_and_one_unsanitized_path() {
    let mut dfg = DataflowGraph::new();

    let v_src = SsaVar::new("user_val", 0, "branching", 10);
    let v_clean_branch = SsaVar::new("clean_branch", 1, "branching", 15);
    let v_raw_branch = SsaVar::new("raw_branch", 1, "branching", 18);
    let v_sink = SsaVar::new("merged_sql", 0, "branching", 25);

    dfg.add_source(TaintSource::new(v_src.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    dfg.add_sink(TaintSink::new(v_sink.clone(), SinkKind::SqlExecution, "CWE-89"));

    // Branch 1: Sanitized
    dfg.add_edge(sanitized_edge(
        v_src.clone(),
        v_clean_branch.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "clean_sql".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        15,
        "clean_sql",
    ));
    dfg.add_edge(edge(v_clean_branch.clone(), v_sink.clone(), TaintStepKind::PhiJoin, 25));

    // Branch 2: Raw / Unsanitized
    dfg.add_edge(edge(v_src.clone(), v_raw_branch.clone(), TaintStepKind::DirectAssignment, 18));
    dfg.add_edge(edge(v_raw_branch.clone(), v_sink.clone(), TaintStepKind::PhiJoin, 25));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    // Because there is at least one un-sanitized path reaching the sink,
    // the conservative security rule dictates that the flow is VULNERABLE!
    assert!(!traces[0].is_sanitized, "Unsanitized path exists; cannot be considered fully sanitized");
    assert!(traces[0].is_vulnerable, "Alert must be triggered because an unsanitized branch exists");
}

#[test]
fn test_r2_tier2_disconnected_variable_no_alert() {
    let mut dfg = DataflowGraph::new();

    let v_src = SsaVar::new("tainted_var", 0, "isolated", 10);
    let v_sink = SsaVar::new("safe_constant", 0, "isolated", 20);

    dfg.add_source(TaintSource::new(v_src.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    dfg.add_sink(TaintSink::new(v_sink.clone(), SinkKind::SqlExecution, "CWE-89"));

    // No edge connects v_src to v_sink!
    let traces = dfg.track_dataflow();
    assert!(traces.is_empty(), "Zero traces expected when source does not reach sink");
}

#[test]
fn test_r2_tier2_nested_sanitizers_safety() {
    let mut dfg = DataflowGraph::new();

    let v0 = SsaVar::new("x", 0, "fn", 10);
    let v1 = SsaVar::new("x", 1, "fn", 12);
    let v2 = SsaVar::new("x", 2, "fn", 14);
    let v_sink = SsaVar::new("target", 0, "fn", 16);

    dfg.add_source(TaintSource::new(v0.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    dfg.add_sink(TaintSink::new(v_sink.clone(), SinkKind::SqlExecution, "CWE-89"));

    // Nested sanitizers: clean_sql followed by intval
    dfg.add_edge(sanitized_edge(v0.clone(), v1.clone(), TaintStepKind::DirectAssignment, 12, "clean_sql"));
    dfg.add_edge(sanitized_edge(v1.clone(), v2.clone(), TaintStepKind::DirectAssignment, 14, "intval"));
    dfg.add_edge(edge(v2.clone(), v_sink.clone(), TaintStepKind::DirectAssignment, 16));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    assert!(traces[0].is_sanitized);
    assert!(!traces[0].is_vulnerable);
    assert!(traces[0].applied_sanitizers.contains(&"clean_sql".to_string()));
    assert!(traces[0].applied_sanitizers.contains(&"intval".to_string()));
}
