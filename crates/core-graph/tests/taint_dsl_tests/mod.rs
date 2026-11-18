use core_graph::{
    track_dataflow, AetherGraph, DataflowEdge, DataflowGraph, SanitizerMatchKind, SanitizerRule,
    SinkKind, SourceKind, SsaVar, TaintRuleSet, TaintSink, TaintSinkRule, TaintSource,
    TaintSourceRule, TaintStepKind,
};
use core_graph::dataflow::{
    language_matches, normalize_language, TaintRuleSet as DataflowTaintRuleSet,
    TaintSinkRule as DataflowTaintSinkRule, TaintSourceRule as DataflowTaintSourceRule,
};

#[test]
fn test_taint_rule_serde_json_roundtrip() {
    let mut rules = TaintRuleSet::new();
    rules.add_source(
        TaintSourceRule::new(
            "flask_args",
            SourceKind::HttpQueryParam,
            "CWE-89",
            vec!["request.args.get".to_string(), "request.args[*]".to_string()],
        )
        .with_language("python")
        .with_description("Flask query arguments"),
    );
    rules.add_source(
        TaintSourceRule::new(
            "custom_ipc",
            SourceKind::Custom("IPC".to_string()),
            "*",
            vec!["ipc_recv(".to_string()],
        )
        .with_description("Custom IPC source"),
    );
    rules.add_sink(
        TaintSinkRule::new(
            "sqlite_exec",
            SinkKind::SqlExecution,
            "CWE-89",
            vec!["cursor.execute(".to_string()],
        )
        .with_rule("PY-SQLI-001", "CRITICAL")
        .with_language("py")
        .with_description("SQLite query execution"),
    );
    rules.add_sanitizer(
        SanitizerRule::new(
            "parameterize",
            vec!["CWE-89".to_string()],
            SanitizerMatchKind::MethodCall,
        )
        .with_language("python"),
    );

    let json = serde_json::to_string(&rules).expect("serialize TaintRuleSet");
    let decoded: TaintRuleSet = serde_json::from_str(&json).expect("deserialize TaintRuleSet");
    assert_eq!(decoded, rules);
}

#[test]
fn test_taint_rule_serde_defaults_minimal_payload() {
    let empty_set: TaintRuleSet = serde_json::from_str("{}").expect("empty object to TaintRuleSet");
    assert!(empty_set.is_empty());

    let src: TaintSourceRule =
        serde_json::from_str(r#"{"name": "req_input"}"#).expect("minimal TaintSourceRule");
    assert_eq!(src.name, "req_input");
    assert_eq!(src.source_kind, SourceKind::Custom("custom".to_string()));
    assert_eq!(src.cwe, "");
    assert!(src.patterns.is_empty());
    assert_eq!(src.language, None);
    assert_eq!(src.description, "");

    let sink: TaintSinkRule =
        serde_json::from_str(r#"{"name": "eval_sink"}"#).expect("minimal TaintSinkRule");
    assert_eq!(sink.name, "eval_sink");
    assert_eq!(sink.sink_kind, SinkKind::Custom("custom".to_string()));
    assert_eq!(sink.severity, "HIGH");
    assert_eq!(sink.cwe, "");
    assert_eq!(sink.rule_id, "");
    assert!(sink.patterns.is_empty());
    assert_eq!(sink.language, None);
    assert_eq!(sink.description, "");

    let default_sink = TaintSinkRule::default();
    assert_eq!(default_sink.severity, "HIGH");

    let san: SanitizerRule =
        serde_json::from_str(r#"{"name": "clean_fn"}"#).expect("minimal SanitizerRule");
    assert_eq!(san.name, "clean_fn");
    assert!(san.target_cwes.is_empty());
    assert_eq!(san.match_kind, SanitizerMatchKind::ExactName);
    assert_eq!(san.language, None);
    assert!(!san.neutralizes_all);

    let san_default = SanitizerRule::default();
    assert_eq!(san_default.match_kind, SanitizerMatchKind::ExactName);
}

#[test]
fn test_source_and_sink_kind_backwards_compat_serde() {
    assert_eq!(SourceKind::default(), SourceKind::Custom("custom".to_string()));
    assert_eq!(SourceKind::default().to_string(), "Custom (custom)");
    assert_eq!(SinkKind::default(), SinkKind::Custom("custom".to_string()));
    assert_eq!(SinkKind::default().to_string(), "Custom (custom)");
    assert_eq!(SanitizerMatchKind::default(), SanitizerMatchKind::ExactName);

    let src = TaintSource::new(
        SsaVar::new("q", 0, "main", 1),
        SourceKind::HttpQueryParam,
        "CWE-89",
    );
    let src_json = serde_json::to_string(&src).unwrap();
    assert!(src_json.contains(r#""source_kind":"HttpQueryParam""#));
    let src_back: TaintSource = serde_json::from_str(&src_json).unwrap();
    assert_eq!(src_back, src);

    let custom_sink = TaintSink::new(
        SsaVar::new("x", 0, "main", 2),
        SinkKind::Custom("MyKind".to_string()),
        "CWE-502",
    );
    let sink_json = serde_json::to_string(&custom_sink).unwrap();
    assert!(sink_json.contains(r#""sink_kind":{"Custom":"MyKind"}"#));
    let sink_back: TaintSink = serde_json::from_str(&sink_json).unwrap();
    assert_eq!(sink_back, custom_sink);

    let san = SanitizerRule::new(
        "intval",
        vec!["CWE-89".to_string()],
        SanitizerMatchKind::ExactName,
    );
    let san_json = serde_json::to_string(&san).unwrap();
    assert_eq!(
        san_json,
        r#"{"name":"intval","target_cwes":["CWE-89"],"match_kind":"ExactName","language":null,"neutralizes_all":false}"#
    );
    let san_back: SanitizerRule = serde_json::from_str(&san_json).unwrap();
    assert_eq!(san_back, san);

    let alias_src_kind: SourceKind = serde_json::from_str(r#""http_query_param""#).unwrap();
    assert_eq!(alias_src_kind, SourceKind::HttpQueryParam);
    let alias_sink_kind: SinkKind = serde_json::from_str(r#""sql_execution""#).unwrap();
    assert_eq!(alias_sink_kind, SinkKind::SqlExecution);
}

#[test]
fn test_taint_rule_set_is_empty() {
    let empty = TaintRuleSet::default();
    assert!(empty.is_empty());

    let mut only_src = TaintRuleSet::new();
    only_src.add_source(TaintSourceRule::new("s", SourceKind::default(), "", vec![]));
    assert!(!only_src.is_empty());

    let mut only_sink = TaintRuleSet::new();
    only_sink.add_sink(TaintSinkRule::new("k", SinkKind::default(), "", vec![]));
    assert!(!only_sink.is_empty());

    let mut only_san = TaintRuleSet::new();
    only_san.add_sanitizer(SanitizerRule::new_all("clean", SanitizerMatchKind::ExactName));
    assert!(!only_san.is_empty());
}

#[test]
fn test_taint_rule_set_merge_semantics() {
    let mut a = TaintRuleSet::new();
    let empty = TaintRuleSet::new();
    a.merge(&empty);
    assert!(a.is_empty());

    let src1 = TaintSourceRule::new("s1", SourceKind::HttpBodyParam, "CWE-89", vec!["body".into()]);
    let src2 = TaintSourceRule::new("s2", SourceKind::HttpHeader, "CWE-79", vec!["header".into()]);
    let sink1 = TaintSinkRule::new("k1", SinkKind::SqlExecution, "CWE-89", vec!["query(".into()]);
    let san1 = SanitizerRule::new("esc", vec!["CWE-79".into()], SanitizerMatchKind::ExactName);

    let mut b = TaintRuleSet::new();
    b.add_source(src1.clone());
    b.add_sink(sink1.clone());
    b.add_sanitizer(san1.clone());

    a.merge(&b);
    assert_eq!(a, b);

    a.merge(&empty);
    assert_eq!(a, b);

    // Self-merge idempotence
    let snapshot = a.clone();
    a.merge(&snapshot);
    assert_eq!(a, snapshot);

    // Order-preserving merge with overlapping + new rules
    let mut c = TaintRuleSet::new();
    c.add_source(src1.clone());
    c.add_source(src2.clone());
    a.merge(&c);
    assert_eq!(a.sources, vec![src1, src2]);
    assert_eq!(a.sinks.len(), 1);
    assert_eq!(a.sanitizers.len(), 1);
}

#[test]
fn test_taint_rule_language_normalization_and_filtering() {
    assert_eq!(normalize_language("rs"), Some("rust"));
    assert_eq!(normalize_language("src/main.rs"), Some("rust"));
    assert_eq!(normalize_language("C:\\app\\Program.CS"), Some("csharp"));
    assert_eq!(normalize_language("c#"), Some("csharp"));
    assert_eq!(normalize_language("app.mjs"), Some("javascript"));
    assert_eq!(normalize_language("App.tsx"), Some("typescript"));
    assert_eq!(normalize_language("index.phtml"), Some("php"));
    assert_eq!(normalize_language("script.luau"), Some("lua"));
    assert_eq!(normalize_language(""), None);

    assert!(language_matches(None, "rust"));
    assert!(language_matches(Some("*"), "src/lib.py"));
    assert!(language_matches(Some("all"), "main.zig"));
    assert!(language_matches(Some("any"), ""));
    assert!(language_matches(Some("py"), "Python"));
    assert!(language_matches(Some("javascript"), "routes/users.cjs"));
    assert!(!language_matches(Some("javascript"), "routes/users.ts"));
    assert!(!language_matches(Some("php"), "rust"));
    assert!(!language_matches(Some("rust"), ""));

    let mut set = TaintRuleSet::new();
    set.add_source(
        TaintSourceRule::new("py_src", SourceKind::HttpQueryParam, "CWE-89", vec!["request.args".into()])
            .with_language("py"),
    );
    set.add_source(
        TaintSourceRule::new("any_src", SourceKind::FunctionArgument, "*", vec!["argv".into()]),
    );
    set.add_sink(
        TaintSinkRule::new("cs_sink", SinkKind::SqlExecution, "CWE-89", vec!["FromSqlRaw".into()])
            .with_language("C#"),
    );
    set.add_sanitizer(
        SanitizerRule::new("shlex.quote", vec!["CWE-78".into()], SanitizerMatchKind::MethodCall)
            .with_language("python"),
    );

    assert_eq!(set.sources_for_language("api/view.py").len(), 2);
    assert_eq!(set.sources_for_language("src/main.rs").len(), 1);
    assert_eq!(set.sinks_for_language("Controllers/Db.cs").len(), 1);
    assert_eq!(set.sinks_for_language("app.py").len(), 0);
    assert_eq!(set.sanitizers_for_language("worker.py").len(), 1);
    assert_eq!(set.sanitizers_for_language("worker.js").len(), 0);
    assert!(set.sanitizers[0].matches_for_path("shlex.quote(cmd)", "CWE-78", "cli.py"));
    assert!(!set.sanitizers[0].matches_for_path("shlex.quote(cmd)", "CWE-78", "cli.js"));
}

#[test]
fn test_taint_rule_pattern_matching_and_cwe_lookup() {
    let mut set = TaintRuleSet::new();
    let src = TaintSourceRule::new(
        "wild_db_req",
        SourceKind::HttpBodyParam,
        "CWE-89",
        vec!["req.*.body".into(), "".into()],
    )
    .with_language("js");
    let sink_sqli = TaintSinkRule::new(
        "db_query",
        SinkKind::SqlExecution,
        "CWE-89 / SQLI",
        vec!["db.*.query(".into()],
    )
    .with_rule("JS-SQLI-1", "CRITICAL")
    .with_language("javascript");
    let sink_xss = TaintSinkRule::new(
        "dom_xss",
        SinkKind::HtmlRender,
        "CWE-79",
        vec!["innerHTML =".into()],
    )
    .with_language("*");
    let sink_any = TaintSinkRule::new(
        "generic_sink",
        SinkKind::Custom("Generic".into()),
        "*",
        vec!["*".into()],
    );

    set.add_source(src);
    set.add_sink(sink_sqli);
    set.add_sink(sink_xss);
    set.add_sink(sink_any);

    assert_eq!(set.match_sources("const x = req.user.body;", "app.mjs").len(), 1);
    assert_eq!(set.match_sources("const x = body.req;", "app.mjs").len(), 0);
    assert_eq!(set.match_sources("const x = req.user.body;", "app.py").len(), 0);
    assert_eq!(set.match_sinks("  db.users.query(sql);", "routes.js").len(), 2); // db_query + generic_sink
    assert_eq!(set.match_sinks("", "routes.js").len(), 0); // "*" does not match empty line

    let sqli_sinks = set.sinks_for_cwe("CWE-89");
    assert_eq!(sqli_sinks.len(), 2); // "CWE-89 / SQLI" and "*"
    assert_eq!(set.sinks_for_cwe("cwe-89").len(), 2);
    assert_eq!(set.sources_for_cwe("CWE-89").len(), 1);
    assert_eq!(set.sources_for_cwe("CWE-79").len(), 0);

    assert_eq!(set.find_source("wild_db_req").map(|r| r.name.as_str()), Some("wild_db_req"));
    assert_eq!(set.find_sink("JS-SQLI-1").map(|r| r.name.as_str()), Some("db_query"));
    assert_eq!(set.find_sink("dom_xss").map(|r| r.name.as_str()), Some("dom_xss"));
    assert!(set.find_sink("missing").is_none());
}

#[test]
fn test_core_graph_reexports_and_dataflow_integration() {
    // Verify both core_graph::* and core_graph::dataflow::* export the exact same types.
    let _: fn() -> DataflowTaintRuleSet = TaintRuleSet::new;
    let src_rule: DataflowTaintSourceRule = TaintSourceRule::new(
        "custom_env",
        SourceKind::Custom("Env".into()),
        "",
        vec!["env::var(".into()],
    )
    .with_language("rust");
    let sink_rule: DataflowTaintSinkRule = TaintSinkRule::new(
        "cmd_exec",
        SinkKind::CommandExecution,
        "CWE-78",
        vec!["Command::new(".into()],
    )
    .with_language("rs");
    let custom_san = SanitizerRule::new(
        "shell_escape_strict",
        vec!["CWE-78".into()],
        SanitizerMatchKind::ExactName,
    )
    .with_language("rust");

    let mut rule_set = TaintRuleSet::new();
    rule_set.add_source(src_rule.clone());
    rule_set.add_sink(sink_rule.clone());
    rule_set.add_sanitizer(custom_san);

    let matched_src = rule_set.match_sources("let arg = env::var(\"INPUT\");", "src/bin.rs");
    let matched_sink = rule_set.match_sinks("Command::new(cmd);", "src/bin.rs");
    assert_eq!(matched_src.len(), 1);
    assert_eq!(matched_sink.len(), 1);

    let v_src = SsaVar::new("arg", 0, "run", 10).with_file("src/bin.rs");
    let v_mid = SsaVar::new("cmd", 0, "run", 11).with_file("src/bin.rs");
    let v_sink = SsaVar::new("exec_arg", 0, "run", 12).with_file("src/bin.rs");

    let taint_src = matched_src[0].to_taint_source(v_src.clone());
    let taint_sink = matched_sink[0].to_taint_sink(v_sink.clone());
    assert_eq!(taint_src.cwe, "*");
    assert_eq!(taint_sink.rule_id, "cmd_exec");
    assert_eq!(taint_sink.severity, "HIGH");

    // Unsanitized flow
    let mut dfg = DataflowGraph::new();
    dfg.apply_rule_set(&rule_set);
    dfg.apply_rule_set(&rule_set); // idempotent
    let san_count = dfg.sanitizers.iter().filter(|r| r.name == "shell_escape_strict").count();
    assert_eq!(san_count, 1);

    dfg.add_source(taint_src.clone());
    dfg.add_sink(taint_sink.clone());
    dfg.add_edge(DataflowEdge::new(
        v_src.clone(),
        v_mid.clone(),
        TaintStepKind::DirectAssignment,
        11,
        false,
        None,
    ));
    dfg.add_edge(DataflowEdge::new(
        v_mid.clone(),
        v_sink.clone(),
        TaintStepKind::DirectAssignment,
        12,
        false,
        None,
    ));

    let vuln_traces = dfg.track_dataflow();
    assert_eq!(vuln_traces.len(), 1);
    assert!(vuln_traces[0].is_vulnerable);
    assert!(!vuln_traces[0].is_sanitized);

    // Sanitized flow via rule_set.match_sanitizers + track_dataflow
    let matched_sans = rule_set.match_sanitizers("shell_escape_strict", "CWE-78", "src/bin.rs");
    assert_eq!(matched_sans.len(), 1);

    let mut graph = AetherGraph::new("DslIntegration");
    let mut san_dfg = DataflowGraph::new();
    san_dfg.add_edge(DataflowEdge::new(
        v_src.clone(),
        v_mid.clone(),
        TaintStepKind::SanitizerCall {
            sanitizer_name: matched_sans[0].name.clone(),
            cwe_targeted: "CWE-78".to_string(),
        },
        11,
        true,
        Some(matched_sans[0].name.clone()),
    ));
    san_dfg.add_edge(DataflowEdge::new(
        v_mid,
        v_sink,
        TaintStepKind::DirectAssignment,
        12,
        false,
        None,
    ));
    graph.dataflow_graph = Some(san_dfg);

    let traces = track_dataflow(&graph, &[taint_src], &[taint_sink], &[matched_sans[0].clone()]);
    assert_eq!(traces.len(), 1);
    assert!(traces[0].is_sanitized);
    assert!(!traces[0].is_vulnerable);
    assert_eq!(traces[0].applied_sanitizers, vec!["shell_escape_strict"]);
}
