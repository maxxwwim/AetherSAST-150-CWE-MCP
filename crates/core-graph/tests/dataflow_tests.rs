use core_graph::bubble::{CveAnomalyRecord, SymbolBubble, SymbolKind};
use core_graph::dataflow::{
    track_dataflow, DataflowEdge, DataflowGraph, SanitizerMatchKind, SanitizerRule, SinkKind,
    SourceKind, SsaVar, TaintSink, TaintSource, TaintStepKind,
};
use core_graph::graph::AetherGraph;

#[test]
fn test_ssa_var_versioning_and_display() {
    let var0 = SsaVar::new("$user_input", 0, "handle_request", 12).with_file("src/api.php");
    let var1 = SsaVar::new("$user_input", 1, "handle_request", 15).with_file("src/api.php");

    assert_eq!(var0.display_id(), "$user_input#0");
    assert_eq!(var1.display_id(), "$user_input#1");
    assert_eq!(var0.scoped_id(), "handle_request::$user_input#0");
    assert_eq!(var1.scoped_id(), "handle_request::$user_input#1");
    assert_ne!(var0, var1);
}

#[test]
fn test_synthetic_direct_intra_procedural_unsanitized() {
    let mut dfg = DataflowGraph::new();

    // Variable SSA definitions
    let v_source = SsaVar::new("$user_id", 0, "getUser", 10).with_file("api.php");
    let v_query = SsaVar::new("$sql", 0, "getUser", 12).with_file("api.php");

    // Source: HTTP GET
    let source = TaintSource::new(v_source.clone(), SourceKind::HttpQueryParam, "CWE-89")
        .with_description("$_GET['id'] input");
    dfg.add_source(source.clone());

    // Step 1: $sql#0 = "SELECT * FROM users WHERE id = " . $user_id#0
    let edge1 = DataflowEdge::new(
        v_source.clone(),
        v_query.clone(),
        TaintStepKind::BinaryExpression,
        12,
        false,
        None,
    );
    dfg.add_edge(edge1);

    // Sink: query($sql#0)
    let sink = TaintSink::new(v_query.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("CWE-89-SQL-INJECTION", "CRITICAL")
        .with_description("PDO::query call");
    dfg.add_sink(sink.clone());

    // Execute taint tracking
    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1, "Should find 1 propagation trace");

    let trace = &traces[0];
    assert_eq!(trace.is_sanitized, false, "Flow is un-sanitized");
    assert_eq!(trace.is_vulnerable, true, "Sink is vulnerable");
    assert_eq!(trace.steps.len(), 1, "Should have 1 step");

    // Verify exact variable identifier propagation trace
    let vars = trace.traversed_variables();
    assert_eq!(vars, vec!["$user_id#0", "$sql#0"]);

    let scoped_vars = trace.traversed_scoped_variables();
    assert_eq!(scoped_vars, vec!["getUser::$user_id#0", "getUser::$sql#0"]);

    // Active vulnerabilities must contain this alert
    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].sink.rule_id, "CWE-89-SQL-INJECTION");
}

#[test]
fn test_synthetic_direct_intra_procedural_sanitized_neutralized() {
    let mut dfg = DataflowGraph::new();

    // Source -> clean_sql -> query
    let v_source = SsaVar::new("$user_id", 0, "getUser", 10).with_file("api.php");
    let v_clean = SsaVar::new("$safe_id", 0, "getUser", 11).with_file("api.php");
    let v_query = SsaVar::new("$sql", 0, "getUser", 12).with_file("api.php");

    dfg.add_source(TaintSource::new(v_source.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    // Step 1: $safe_id#0 = clean_sql($user_id#0) (Sanitizer)
    let edge1 = DataflowEdge::new(
        v_source.clone(),
        v_clean.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "clean_sql".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        11,
        true,
        Some("clean_sql".to_string()),
    );
    dfg.add_edge(edge1);

    // Step 2: $sql#0 = "SELECT * FROM users WHERE id = " . $safe_id#0
    let edge2 = DataflowEdge::new(
        v_clean.clone(),
        v_query.clone(),
        TaintStepKind::BinaryExpression,
        12,
        false,
        None,
    );
    dfg.add_edge(edge2);

    dfg.add_sink(TaintSink::new(v_query.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("CWE-89-SQL-INJECTION", "CRITICAL"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    let trace = &traces[0];
    assert_eq!(trace.is_sanitized, true, "Flow MUST be marked sanitized");
    assert_eq!(trace.is_vulnerable, false, "Flow MUST NOT be vulnerable");
    assert!(trace.applied_sanitizers.contains(&"clean_sql".to_string()));

    // Crucial Acceptance Criterion: NO active vulnerability alert at Sink level!
    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 0, "Sanitized taint MUST NOT trigger any active vulnerability alert");
}

#[test]
fn test_sanitizers_per_cwe_catalog() {
    let test_cases = vec![
        // (Sanitizer name, Target CWE, Sink Kind, Expected Sanitized)
        ("intval", "CWE-89", SinkKind::SqlExecution, true),
        ("clean_sql", "CWE-89", SinkKind::SqlExecution, true),
        ("prepare", "CWE-89", SinkKind::SqlExecution, true),
        ("pdo_prepare", "CWE-89", SinkKind::SqlExecution, true),
        ("mysqli_real_escape_string", "CWE-89", SinkKind::SqlExecution, true),
        ("escapeshellarg", "CWE-78", SinkKind::CommandExecution, true),
        ("escapeshellcmd", "CWE-78", SinkKind::CommandExecution, true),
        ("shlex.quote", "CWE-78", SinkKind::CommandExecution, true),
        ("htmlspecialchars", "CWE-79", SinkKind::HtmlRender, true),
        ("DOMPurify.sanitize", "CWE-79", SinkKind::HtmlRender, true),
        ("sanitize_input", "CWE-79", SinkKind::HtmlRender, true),
        ("escape_html", "CWE-79", SinkKind::HtmlRender, true),
        ("basename", "CWE-22", SinkKind::FileAccess, true),
        ("sanitize_path", "CWE-22", SinkKind::FileAccess, true),
        ("realpath", "CWE-22", SinkKind::FileAccess, true),
        // Cross-CWE mismatch: HTML sanitizer applied to SQL injection does NOT neutralize SQL!
        ("htmlspecialchars", "CWE-89", SinkKind::SqlExecution, false),
        ("basename", "CWE-78", SinkKind::CommandExecution, false),
    ];

    for (san_name, cwe, sink_kind, should_neutralize) in test_cases {
        let mut dfg = DataflowGraph::new();

        let v0 = SsaVar::new("input", 0, "fn", 1);
        let v1 = SsaVar::new("sanitized", 0, "fn", 2);
        let v2 = SsaVar::new("output", 0, "fn", 3);

        dfg.add_source(TaintSource::new(v0.clone(), SourceKind::HttpQueryParam, cwe));

        dfg.add_edge(DataflowEdge::new(
            v0.clone(),
            v1.clone(),
            TaintStepKind::SanitizerCall {
                sanitizer_name: san_name.to_string(),
                cwe_targeted: cwe.to_string(),
            },
            2,
            true,
            Some(san_name.to_string()),
        ));

        dfg.add_edge(DataflowEdge::new(
            v1.clone(),
            v2.clone(),
            TaintStepKind::DirectAssignment,
            3,
            false,
            None,
        ));

        dfg.add_sink(TaintSink::new(v2.clone(), sink_kind, cwe));

        let traces = dfg.track_dataflow();
        assert_eq!(traces.len(), 1, "Testing {}", san_name);

        let trace = &traces[0];
        if should_neutralize {
            assert!(
                trace.is_sanitized,
                "Sanitizer '{}' for '{}' should have neutralized the taint",
                san_name, cwe
            );
            assert_eq!(trace.is_vulnerable, false);
            assert_eq!(dfg.active_vulnerabilities().len(), 0);
        } else {
            assert!(
                !trace.is_sanitized,
                "Sanitizer '{}' should NOT neutralize unrelated CWE '{}'",
                san_name, cwe
            );
            assert_eq!(trace.is_vulnerable, true);
            assert_eq!(dfg.active_vulnerabilities().len(), 1);
        }
    }
}

#[test]
fn test_synthetic_inter_procedural_multi_hop_unsanitized() {
    let mut dfg = DataflowGraph::new();

    // 4 functions, 4 hops:
    // controller($req#0) -> service($input#0) -> repo($raw#0) -> db($sql#0) -> query($sql#0)
    let v_req = SsaVar::new("$req", 0, "controller", 10).with_file("controller.php");
    let v_input = SsaVar::new("$input", 0, "service", 20).with_file("service.php");
    let v_raw = SsaVar::new("$raw", 0, "repo", 30).with_file("repo.php");
    let v_sql = SsaVar::new("$sql", 0, "db", 40).with_file("db.php");

    // Source at controller
    dfg.add_source(TaintSource::new(v_req.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    // Hop 1: controller -> service
    dfg.add_edge(DataflowEdge::new(
        v_req.clone(),
        v_input.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "controller".to_string(),
            callee_function: "service".to_string(),
            arg_index: 0,
            param_name: "$input".to_string(),
        },
        12,
        false,
        None,
    ));

    // Hop 2: service -> repo
    dfg.add_edge(DataflowEdge::new(
        v_input.clone(),
        v_raw.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "service".to_string(),
            callee_function: "repo".to_string(),
            arg_index: 0,
            param_name: "$raw".to_string(),
        },
        22,
        false,
        None,
    ));

    // Hop 3: repo -> db
    dfg.add_edge(DataflowEdge::new(
        v_raw.clone(),
        v_sql.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "repo".to_string(),
            callee_function: "db".to_string(),
            arg_index: 0,
            param_name: "$sql".to_string(),
        },
        32,
        false,
        None,
    ));

    // Sink at db
    dfg.add_sink(TaintSink::new(v_sql.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("CWE-89-INTER-PROCEDURAL", "CRITICAL"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    let trace = &traces[0];
    assert_eq!(trace.is_sanitized, false);
    assert_eq!(trace.is_vulnerable, true);
    assert_eq!(trace.steps.len(), 3);

    // Exact variable identifier propagation trace
    let vars = trace.traversed_variables();
    assert_eq!(vars, vec!["$req#0", "$input#0", "$raw#0", "$sql#0"]);

    let scoped = trace.traversed_scoped_variables();
    assert_eq!(scoped, vec![
        "controller::$req#0",
        "service::$input#0",
        "repo::$raw#0",
        "db::$sql#0"
    ]);

    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 1);
}

#[test]
fn test_synthetic_inter_procedural_multi_hop_sanitized_neutralized() {
    let mut dfg = DataflowGraph::new();

    // 4 functions, but service neutralizes via clean_sql:
    // controller($req#0) -> service($input#0) -> service($safe#0 = clean_sql($input#0)) -> repo($raw#0) -> db($sql#0)
    let v_req = SsaVar::new("$req", 0, "controller", 10).with_file("controller.php");
    let v_input = SsaVar::new("$input", 0, "service", 20).with_file("service.php");
    let v_safe = SsaVar::new("$safe", 0, "service", 21).with_file("service.php");
    let v_raw = SsaVar::new("$raw", 0, "repo", 30).with_file("repo.php");
    let v_sql = SsaVar::new("$sql", 0, "db", 40).with_file("db.php");

    dfg.add_source(TaintSource::new(v_req.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    // Hop 1: controller -> service
    dfg.add_edge(DataflowEdge::new(
        v_req.clone(),
        v_input.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "controller".to_string(),
            callee_function: "service".to_string(),
            arg_index: 0,
            param_name: "$input".to_string(),
        },
        12,
        false,
        None,
    ));

    // Intermediate Sanitizer in service
    dfg.add_edge(DataflowEdge::new(
        v_input.clone(),
        v_safe.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "clean_sql".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        21,
        true,
        Some("clean_sql".to_string()),
    ));

    // Hop 2: service -> repo with $safe#0
    dfg.add_edge(DataflowEdge::new(
        v_safe.clone(),
        v_raw.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "service".to_string(),
            callee_function: "repo".to_string(),
            arg_index: 0,
            param_name: "$raw".to_string(),
        },
        22,
        false,
        None,
    ));

    // Hop 3: repo -> db
    dfg.add_edge(DataflowEdge::new(
        v_raw.clone(),
        v_sql.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "repo".to_string(),
            callee_function: "db".to_string(),
            arg_index: 0,
            param_name: "$sql".to_string(),
        },
        32,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v_sql.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("CWE-89-INTER-PROCEDURAL", "CRITICAL"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    let trace = &traces[0];
    assert_eq!(trace.is_sanitized, true, "Should be neutralized by intermediate clean_sql");
    assert_eq!(trace.is_vulnerable, false);
    assert_eq!(trace.steps.len(), 4);
    assert!(trace.applied_sanitizers.contains(&"clean_sql".to_string()));

    // Verify traversed variables
    assert_eq!(
        trace.traversed_variables(),
        vec!["$req#0", "$input#0", "$safe#0", "$raw#0", "$sql#0"]
    );

    // Crucial Acceptance Criterion: ZERO alerts at Sink level!
    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 0, "No active alerts allowed for sanitized flow");
}

#[test]
fn test_ssa_version_reassignment_disambiguation() {
    let mut dfg = DataflowGraph::new();

    // $x#0 = $_GET['x']; (Tainted)
    // $x#1 = intval($x#0); (Sanitized)
    // sink1($x#0); -> Must trigger alert!
    // sink2($x#1); -> Must be neutralized!
    let v_x0 = SsaVar::new("$x", 0, "handle", 10).with_file("test.php");
    let v_x1 = SsaVar::new("$x", 1, "handle", 11).with_file("test.php");

    dfg.add_source(TaintSource::new(v_x0.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    dfg.add_edge(DataflowEdge::new(
        v_x0.clone(),
        v_x1.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "intval".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        11,
        true,
        Some("intval".to_string()),
    ));

    let sink1 = TaintSink::new(v_x0.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("SINK_X0", "CRITICAL");
    let sink2 = TaintSink::new(v_x1.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("SINK_X1", "CRITICAL");

    dfg.add_sink(sink1);
    dfg.add_sink(sink2);

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 2);

    let trace_sink1 = traces.iter().find(|t| t.sink.rule_id == "SINK_X0").expect("trace sink1");
    assert_eq!(trace_sink1.is_sanitized, false, "Sink1 consumes $x#0 directly without sanitization");
    assert_eq!(trace_sink1.is_vulnerable, true);

    let trace_sink2 = traces.iter().find(|t| t.sink.rule_id == "SINK_X1").expect("trace sink2");
    assert_eq!(trace_sink2.is_sanitized, true, "Sink2 consumes sanitized $x#1");
    assert_eq!(trace_sink2.is_vulnerable, false);

    // Active vulnerabilities must contain ONLY sink1
    let active = dfg.active_vulnerabilities();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].sink.rule_id, "SINK_X0");
}

#[test]
fn test_inter_procedural_return_value_propagation() {
    let mut dfg = DataflowGraph::new();

    // caller: $raw#0 -> helper($in#0) -> return $out#0 -> $res#0 -> query($res#0)
    let v_raw = SsaVar::new("$raw", 0, "caller", 10).with_file("caller.php");
    let v_in = SsaVar::new("$in", 0, "helper", 20).with_file("helper.php");
    let v_out = SsaVar::new("$out", 0, "helper", 21).with_file("helper.php");
    let v_res = SsaVar::new("$res", 0, "caller", 11).with_file("caller.php");

    dfg.add_source(TaintSource::new(v_raw.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    // Arg pass: $raw#0 -> $in#0
    dfg.add_edge(DataflowEdge::new(
        v_raw.clone(),
        v_in.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "caller".to_string(),
            callee_function: "helper".to_string(),
            arg_index: 0,
            param_name: "$in".to_string(),
        },
        10,
        false,
        None,
    ));

    // Internal helper computation: $out#0 = $in#0
    dfg.add_edge(DataflowEdge::new(
        v_in.clone(),
        v_out.clone(),
        TaintStepKind::DirectAssignment,
        21,
        false,
        None,
    ));

    // Return pass: $out#0 -> $res#0
    dfg.add_edge(DataflowEdge::new(
        v_out.clone(),
        v_res.clone(),
        TaintStepKind::CallReturnPassing {
            caller_function: "caller".to_string(),
            callee_function: "helper".to_string(),
        },
        11,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v_res.clone(), SinkKind::SqlExecution, "CWE-89"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    let trace = &traces[0];
    assert_eq!(trace.is_sanitized, false);
    assert_eq!(trace.is_vulnerable, true);
    assert_eq!(
        trace.traversed_variables(),
        vec!["$raw#0", "$in#0", "$out#0", "$res#0"]
    );
}

#[test]
fn test_inter_procedural_return_value_sanitized() {
    let mut dfg = DataflowGraph::new();

    // caller: $raw#0 -> helper($in#0) -> helper sanitized $out#0 = intval($in#0) -> return $out#0 -> $res#0 -> query($res#0)
    let v_raw = SsaVar::new("$raw", 0, "caller", 10).with_file("caller.php");
    let v_in = SsaVar::new("$in", 0, "helper", 20).with_file("helper.php");
    let v_out = SsaVar::new("$out", 0, "helper", 21).with_file("helper.php");
    let v_res = SsaVar::new("$res", 0, "caller", 11).with_file("caller.php");

    dfg.add_source(TaintSource::new(v_raw.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    dfg.add_edge(DataflowEdge::new(
        v_raw.clone(),
        v_in.clone(),
        TaintStepKind::CallArgumentPassing {
            caller_function: "caller".to_string(),
            callee_function: "helper".to_string(),
            arg_index: 0,
            param_name: "$in".to_string(),
        },
        10,
        false,
        None,
    ));

    // Helper applies intval
    dfg.add_edge(DataflowEdge::new(
        v_in.clone(),
        v_out.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "intval".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        21,
        true,
        Some("intval".to_string()),
    ));

    dfg.add_edge(DataflowEdge::new(
        v_out.clone(),
        v_res.clone(),
        TaintStepKind::CallReturnPassing {
            caller_function: "caller".to_string(),
            callee_function: "helper".to_string(),
        },
        11,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v_res.clone(), SinkKind::SqlExecution, "CWE-89"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    let trace = &traces[0];
    assert_eq!(trace.is_sanitized, true, "Return value passed through intval must be sanitized");
    assert_eq!(trace.is_vulnerable, false);
    assert_eq!(dfg.active_vulnerabilities().len(), 0);
}

#[test]
fn test_phi_branching_conservative_taint() {
    let mut dfg = DataflowGraph::new();

    // if (cond) { $x_then = clean_sql($in); } else { $x_else = $in; }
    // $x_phi = phi($x_then, $x_else);
    // sink($x_phi);
    let v_in = SsaVar::new("$in", 0, "branch_fn", 1);
    let v_then = SsaVar::new("$x_then", 0, "branch_fn", 2);
    let v_else = SsaVar::new("$x_else", 0, "branch_fn", 4);
    let v_phi = SsaVar::new("$x_phi", 0, "branch_fn", 6);

    dfg.add_source(TaintSource::new(v_in.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    // Path 1 (Then): sanitized
    dfg.add_edge(DataflowEdge::new(
        v_in.clone(),
        v_then.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "clean_sql".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        2,
        true,
        Some("clean_sql".to_string()),
    ));
    dfg.add_edge(DataflowEdge::new(
        v_then.clone(),
        v_phi.clone(),
        TaintStepKind::PhiJoin,
        6,
        false,
        None,
    ));

    // Path 2 (Else): un-sanitized
    dfg.add_edge(DataflowEdge::new(
        v_in.clone(),
        v_else.clone(),
        TaintStepKind::DirectAssignment,
        4,
        false,
        None,
    ));
    dfg.add_edge(DataflowEdge::new(
        v_else.clone(),
        v_phi.clone(),
        TaintStepKind::PhiJoin,
        6,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v_phi.clone(), SinkKind::SqlExecution, "CWE-89"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);

    let trace = &traces[0];
    // Conservative analysis: because un-sanitized else branch can reach sink, flow is VULNERABLE!
    assert_eq!(trace.is_vulnerable, true);
    assert_eq!(trace.is_sanitized, false);
    assert_eq!(dfg.active_vulnerabilities().len(), 1);
}

#[test]
fn test_custom_sanitizer_rule_extension() {
    let mut dfg = DataflowGraph::new();

    // Register custom user rule
    let custom_rule = SanitizerRule::new(
        "my_corp_sql_sanitizer",
        vec!["CWE-89".to_string()],
        SanitizerMatchKind::ExactName,
    );
    dfg.add_sanitizer(custom_rule);

    let v0 = SsaVar::new("input", 0, "fn", 1);
    let v1 = SsaVar::new("clean", 0, "fn", 2);
    let v2 = SsaVar::new("sql", 0, "fn", 3);

    dfg.add_source(TaintSource::new(v0.clone(), SourceKind::HttpQueryParam, "CWE-89"));

    dfg.add_edge(DataflowEdge::new(
        v0.clone(),
        v1.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "my_corp_sql_sanitizer".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        2,
        true,
        Some("my_corp_sql_sanitizer".to_string()),
    ));

    dfg.add_edge(DataflowEdge::new(
        v1.clone(),
        v2.clone(),
        TaintStepKind::DirectAssignment,
        3,
        false,
        None,
    ));

    dfg.add_sink(TaintSink::new(v2.clone(), SinkKind::SqlExecution, "CWE-89"));

    let traces = dfg.track_dataflow();
    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].is_sanitized, true);
    assert_eq!(traces[0].is_vulnerable, false);
    assert_eq!(dfg.active_vulnerabilities().len(), 0);
}

#[test]
fn test_aether_graph_compute_dataflow_taint_integration() {
    let mut graph = AetherGraph::new("TestProject");

    // Create a node with CVE anomaly
    let mut node = SymbolBubble::new(
        "api::getUser".to_string(),
        "getUser".to_string(),
        "src/api.php".to_string(),
        10,
        SymbolKind::Function,
        "server".to_string(),
        "action".to_string(),
    );
    node.has_security_violation = true;

    let anomaly = CveAnomalyRecord {
        rule_id: "PHP-SQLI".to_string(),
        cve_id: "CWE-89 / SQL-INJECTION".to_string(),
        severity: "CRITICAL".to_string(),
        line_number: 15,
        file_path: "src/api.php".to_string(),
        message: "SQL execution with tainted input".to_string(),
        transmitted_data: Some("$sql".to_string()),
        is_reachable: false,
        ..Default::default()
    };
    node.metadata.cve_anomalies.push(anomaly);
    graph.add_node(node);

    // Build dataflow graph with un-sanitized trace
    let mut dfg = DataflowGraph::new();
    let v_src = SsaVar::new("$id", 0, "getUser", 10).with_file("src/api.php");
    let v_sink = SsaVar::new("$sql", 0, "getUser", 15).with_file("src/api.php");

    dfg.add_source(TaintSource::new(v_src.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    dfg.add_edge(DataflowEdge::new(
        v_src.clone(),
        v_sink.clone(),
        TaintStepKind::BinaryExpression,
        12,
        false,
        None,
    ));
    dfg.add_sink(TaintSink::new(v_sink.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("PHP-SQLI", "CRITICAL"));

    graph.dataflow_graph = Some(dfg);

    // Case 1: Unsanitized flow
    let traces = graph.compute_dataflow_taint(&[]);
    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].is_sanitized, false);

    let anom = &graph.nodes[0].metadata.cve_anomalies[0];
    assert!(anom.taint_trace.is_some());
    assert_eq!(anom.is_reachable, true, "Unsanitized flow makes anomaly reachable");
    assert_eq!(graph.nodes[0].has_security_violation, true);

    // Case 2: Now neutralize with sanitizer
    let mut sanitized_dfg = DataflowGraph::new();
    let v_clean = SsaVar::new("$safe", 0, "getUser", 11).with_file("src/api.php");

    sanitized_dfg.add_source(TaintSource::new(v_src.clone(), SourceKind::HttpQueryParam, "CWE-89"));
    sanitized_dfg.add_edge(DataflowEdge::new(
        v_src.clone(),
        v_clean.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: "intval".to_string(),
            cwe_targeted: "CWE-89".to_string(),
        },
        11,
        true,
        Some("intval".to_string()),
    ));
    sanitized_dfg.add_edge(DataflowEdge::new(
        v_clean.clone(),
        v_sink.clone(),
        TaintStepKind::DirectAssignment,
        15,
        false,
        None,
    ));
    sanitized_dfg.add_sink(TaintSink::new(v_sink.clone(), SinkKind::SqlExecution, "CWE-89")
        .with_rule("PHP-SQLI", "CRITICAL"));

    graph.dataflow_graph = Some(sanitized_dfg);

    let san_traces = graph.compute_dataflow_taint(&[]);
    assert_eq!(san_traces.len(), 1);
    assert_eq!(san_traces[0].is_sanitized, true);

    let neutralized_anom = &graph.nodes[0].metadata.cve_anomalies[0];
    assert_eq!(neutralized_anom.is_reachable, false, "Sanitized flow neutralizes anomaly reachability");
    assert_eq!(graph.nodes[0].has_security_violation, false, "Node violation cleared when all anomalies neutralized");
}

#[test]
fn test_track_dataflow_api_standalone() {
    let mut graph = AetherGraph::new("StandaloneProject");
    let mut dfg = DataflowGraph::new();

    let v_src = SsaVar::new("src", 0, "fn", 1);
    let v_sink = SsaVar::new("sink", 0, "fn", 2);

    dfg.add_edge(DataflowEdge::new(
        v_src.clone(),
        v_sink.clone(),
        TaintStepKind::DirectAssignment,
        2,
        false,
        None,
    ));
    graph.dataflow_graph = Some(dfg);

    let sources = vec![TaintSource::new(v_src, SourceKind::HttpQueryParam, "CWE-89")];
    let sinks = vec![TaintSink::new(v_sink, SinkKind::SqlExecution, "CWE-89")];
    let sanitizers = vec![SanitizerRule::new("intval", vec!["CWE-89".to_string()], SanitizerMatchKind::ExactName)];

    let traces = track_dataflow(&graph, &sources, &sinks, &sanitizers);
    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].is_vulnerable, true);
    assert_eq!(traces[0].is_sanitized, false);
}
