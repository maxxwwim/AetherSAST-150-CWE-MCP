use core_graph::bubble::{CveAnomalyRecord, SymbolBubble, SymbolKind};
use core_graph::edge::{AffiliationEdge, EdgeType, FilterAffiliation};
use core_graph::graph::AetherGraph;
use core_graph::reachability::compute_reachability;

fn make_test_node(id: &str, kind: SymbolKind) -> SymbolBubble {
    SymbolBubble::new(
        id.to_string(),
        id.to_string(),
        format!("src/{}.rs", id),
        10,
        kind,
        "server".to_string(),
        "domain".to_string(),
    )
}

fn make_cve(rule_id: &str) -> CveAnomalyRecord {
    CveAnomalyRecord {
        rule_id: rule_id.to_string(),
        cve_id: format!("CVE-{}", rule_id),
        severity: "HIGH".to_string(),
        line_number: 42,
        file_path: "src/test.rs".to_string(),
        message: "Test vulnerability".to_string(),
        remediation: "Apply patch".to_string(),
        ..Default::default()
    }
}

#[test]
fn test_direct_endpoint_sink_reachable() {
    let mut graph = AetherGraph::new("test");
    let mut ep = make_test_node("ep_direct", SymbolKind::FormOrEndpoint);
    ep.metadata.cve_anomalies.push(make_cve("CWE-79"));
    graph.add_node(ep);

    compute_reachability(&mut graph);

    let sink = &graph.nodes[0];
    assert!(sink.metadata.cve_anomalies[0].is_reachable);
    assert_eq!(
        sink.metadata.cve_anomalies[0].exploit_path,
        vec!["ep_direct".to_string()]
    );
}

#[test]
fn test_multi_hop_source_to_sink() {
    let mut graph = AetherGraph::new("test");
    let ep = make_test_node("ep", SymbolKind::FormOrEndpoint);
    let handler = make_test_node("handler", SymbolKind::Function);
    let service = make_test_node("service", SymbolKind::Function);
    let mut sink = make_test_node("sink", SymbolKind::Function);
    sink.metadata.cve_anomalies.push(make_cve("CWE-89"));

    graph.add_node(ep);
    graph.add_node(handler);
    graph.add_node(service);
    graph.add_node(sink);

    graph.add_edge(AffiliationEdge::new(
        "ep".to_string(),
        "handler".to_string(),
        EdgeType::NetworkRPC,
        FilterAffiliation::NETWORK_RPC | FilterAffiliation::PHYSICAL,
    ));
    graph.add_edge(AffiliationEdge::new(
        "handler".to_string(),
        "service".to_string(),
        EdgeType::Call,
        FilterAffiliation::SEMANTIC,
    ));
    graph.add_edge(AffiliationEdge::new(
        "service".to_string(),
        "sink".to_string(),
        EdgeType::Call,
        FilterAffiliation::SEMANTIC,
    ));

    compute_reachability(&mut graph);

    let sink_node = graph.nodes.iter().find(|n| n.id == "sink").unwrap();
    let anom = &sink_node.metadata.cve_anomalies[0];
    assert!(anom.is_reachable);
    assert_eq!(
        anom.exploit_path,
        vec![
            "ep".to_string(),
            "handler".to_string(),
            "service".to_string(),
            "sink".to_string()
        ]
    );
}

#[test]
fn test_unreachable_isolated_sink() {
    let mut graph = AetherGraph::new("test");
    let ep = make_test_node("ep", SymbolKind::FormOrEndpoint);
    let mut isolated = make_test_node("isolated", SymbolKind::Function);
    isolated.metadata.cve_anomalies.push(make_cve("CWE-20"));

    graph.add_node(ep);
    graph.add_node(isolated);

    compute_reachability(&mut graph);

    let node = graph.nodes.iter().find(|n| n.id == "isolated").unwrap();
    assert!(!node.metadata.cve_anomalies[0].is_reachable);
    assert!(node.metadata.cve_anomalies[0].exploit_path.is_empty());
}

#[test]
fn test_non_semantic_edge_ignored() {
    let mut graph = AetherGraph::new("test");
    let ep = make_test_node("ep", SymbolKind::FormOrEndpoint);
    let mut sink = make_test_node("sink", SymbolKind::Function);
    sink.metadata.cve_anomalies.push(make_cve("CWE-78"));

    graph.add_node(ep);
    graph.add_node(sink);

    // Physical containment edge only
    graph.add_edge(AffiliationEdge::new(
        "ep".to_string(),
        "sink".to_string(),
        EdgeType::Contains,
        FilterAffiliation::PHYSICAL,
    ));

    compute_reachability(&mut graph);

    let sink_node = graph.nodes.iter().find(|n| n.id == "sink").unwrap();
    assert!(!sink_node.metadata.cve_anomalies[0].is_reachable);
    assert!(sink_node.metadata.cve_anomalies[0].exploit_path.is_empty());
}

#[test]
fn test_cyclic_graph_termination() {
    let mut graph = AetherGraph::new("test");
    let ep = make_test_node("ep", SymbolKind::FormOrEndpoint);
    let node_a = make_test_node("A", SymbolKind::Function);
    let node_b = make_test_node("B", SymbolKind::Function);
    let mut sink = make_test_node("sink", SymbolKind::Function);
    sink.metadata.cve_anomalies.push(make_cve("CWE-502"));

    graph.add_node(ep);
    graph.add_node(node_a);
    graph.add_node(node_b);
    graph.add_node(sink);

    // ep -> A -> B -> A (cycle) and B -> sink
    graph.add_edge(AffiliationEdge::new(
        "ep".to_string(),
        "A".to_string(),
        EdgeType::Call,
        FilterAffiliation::SEMANTIC,
    ));
    graph.add_edge(AffiliationEdge::new(
        "A".to_string(),
        "B".to_string(),
        EdgeType::Call,
        FilterAffiliation::SEMANTIC,
    ));
    graph.add_edge(AffiliationEdge::new(
        "B".to_string(),
        "A".to_string(),
        EdgeType::Call,
        FilterAffiliation::SEMANTIC,
    ));
    graph.add_edge(AffiliationEdge::new(
        "B".to_string(),
        "sink".to_string(),
        EdgeType::Call,
        FilterAffiliation::SEMANTIC,
    ));

    compute_reachability(&mut graph);

    let sink_node = graph.nodes.iter().find(|n| n.id == "sink").unwrap();
    assert!(sink_node.metadata.cve_anomalies[0].is_reachable);
    assert_eq!(
        sink_node.metadata.cve_anomalies[0].exploit_path,
        vec![
            "ep".to_string(),
            "A".to_string(),
            "B".to_string(),
            "sink".to_string()
        ]
    );
}

#[test]
fn test_multiple_sinks_independent_reachability() {
    let mut graph = AetherGraph::new("test");
    let ep = make_test_node("ep", SymbolKind::FormOrEndpoint);
    let mut reachable_sink = make_test_node("sink_reach", SymbolKind::Function);
    reachable_sink
        .metadata
        .cve_anomalies
        .push(make_cve("CWE-89"));

    let mut unreachable_sink = make_test_node("sink_unreach", SymbolKind::Function);
    unreachable_sink
        .metadata
        .cve_anomalies
        .push(make_cve("CWE-79"));

    graph.add_node(ep);
    graph.add_node(reachable_sink);
    graph.add_node(unreachable_sink);

    graph.add_edge(AffiliationEdge::new(
        "ep".to_string(),
        "sink_reach".to_string(),
        EdgeType::NetworkRPC,
        FilterAffiliation::NETWORK_RPC,
    ));

    compute_reachability(&mut graph);

    let r = graph.nodes.iter().find(|n| n.id == "sink_reach").unwrap();
    assert!(r.metadata.cve_anomalies[0].is_reachable);
    assert_eq!(
        r.metadata.cve_anomalies[0].exploit_path,
        vec!["ep".to_string(), "sink_reach".to_string()]
    );

    let u = graph
        .nodes
        .iter()
        .find(|n| n.id == "sink_unreach")
        .unwrap();
    assert!(!u.metadata.cve_anomalies[0].is_reachable);
    assert!(u.metadata.cve_anomalies[0].exploit_path.is_empty());
}

#[test]
fn test_synthetic_api_prefix_source() {
    let mut graph = AetherGraph::new("test");
    let api_node = make_test_node("api::/auth/login", SymbolKind::Function);
    let mut sink = make_test_node("auth_sink", SymbolKind::Function);
    sink.metadata.cve_anomalies.push(make_cve("CWE-287"));

    graph.add_node(api_node);
    graph.add_node(sink);

    graph.add_edge(AffiliationEdge::new(
        "api::/auth/login".to_string(),
        "auth_sink".to_string(),
        EdgeType::Call,
        FilterAffiliation::SEMANTIC,
    ));

    compute_reachability(&mut graph);

    let s = graph.nodes.iter().find(|n| n.id == "auth_sink").unwrap();
    assert!(s.metadata.cve_anomalies[0].is_reachable);
    assert_eq!(
        s.metadata.cve_anomalies[0].exploit_path,
        vec!["api::/auth/login".to_string(), "auth_sink".to_string()]
    );
}
