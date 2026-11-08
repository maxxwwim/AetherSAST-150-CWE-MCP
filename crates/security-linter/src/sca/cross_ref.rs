use crate::sca::ScaReport;
use core_graph::bubble::{CveAnomalyRecord, SymbolBubble, SymbolKind};
use core_graph::edge::{AffiliationEdge, EdgeType, FilterAffiliation};
use core_graph::graph::AetherGraph;
use core_graph::reachability::compute_reachability;

/// Matches a method call expression against a package and its affected function list
fn call_matches_target(call: &str, pkg: &str, fns: &[String]) -> bool {
    let call_clean = call.trim();
    if call_clean.is_empty() {
        return false;
    }

    if !fns.is_empty() {
        for f in fns {
            let f_clean = f.trim();
            if call_clean == f_clean {
                return true;
            }
            if call_clean.ends_with(f_clean) {
                return true;
            }
            if f_clean.ends_with(call_clean) && call_clean.contains("::") {
                return true;
            }

            let fn_short = f_clean.rsplit("::").next().unwrap_or(f_clean);
            let call_short = call_clean.rsplit("::").next().unwrap_or(call_clean);
            if fn_short == call_short && call_clean.contains(pkg) {
                return true;
            }
        }
    } else {
        // Package-wide advisory: matches any direct reference to the package
        if call_clean.contains(pkg) {
            return true;
        }
    }

    false
}

/// Cross-references vulnerable SCA dependencies against the AetherGraph call-graph
/// to partition findings into reachable endpoints vs dead/uncalled dependencies.
pub fn cross_reference_reachability(graph: &mut AetherGraph, report: &mut ScaReport) {
    if report.vulnerabilities.is_empty() {
        return;
    }

    // 1. Materialize / locate dependency sink nodes in the graph
    for vuln in &report.vulnerabilities {
        let pkg_name = &vuln.dependency.name;

        let sink_ids: Vec<String> = if !vuln.affected_functions.is_empty() {
            vuln.affected_functions
                .iter()
                .map(|f| {
                    // Check if an existing node in graph matches crate::<pkg>::<fn> or dep::<pkg>::<fn>
                    let cand1 = format!("dep::{}::{}", pkg_name, f);
                    let cand2 = format!("crate::{}::{}", pkg_name, f);
                    let cand3 = format!("dep::{}", f);
                    let cand4 = f.clone();

                    if graph.nodes.iter().any(|n| n.id == cand2) {
                        cand2
                    } else if graph.nodes.iter().any(|n| n.id == cand1) {
                        cand1
                    } else if graph.nodes.iter().any(|n| n.id == cand3) {
                        cand3
                    } else if graph.nodes.iter().any(|n| n.id == cand4) {
                        cand4
                    } else {
                        cand1
                    }
                })
                .collect()
        } else {
            let cand1 = format!("dep::{}", pkg_name);
            let cand2 = format!("crate::{}", pkg_name);
            if graph.nodes.iter().any(|n| n.id == cand2) {
                vec![cand2]
            } else {
                vec![cand1]
            }
        };

        for sink_id in sink_ids {
            let anomaly_record = CveAnomalyRecord {
                rule_id: format!("SCA-{}", vuln.advisory_id),
                cve_id: vuln.cve_id.clone(),
                severity: vuln.severity.clone(),
                line_number: 1,
                file_path: vuln.dependency.manifest_file.clone(),
                message: vuln.summary.clone(),
                transmitted_data: Some(format!(
                    "Dependency: {} v{}",
                    vuln.dependency.name, vuln.dependency.version
                )),
                transmitted_type: Some("SCA".to_string()),
                remediation: vuln.remediation.clone(),
                is_reachable: false,
                exploit_path: Vec::new(),
                ..Default::default()
            };

            // If node already exists, ensure the anomaly is attached
            if let Some(existing_node) = graph.nodes.iter_mut().find(|n| n.id == sink_id) {
                if !existing_node
                    .metadata
                    .cve_anomalies
                    .iter()
                    .any(|a| a.cve_id == vuln.cve_id || a.rule_id == anomaly_record.rule_id)
                {
                    existing_node.metadata.cve_anomalies.push(anomaly_record);
                }
            } else {
                // Otherwise materialize a new dependency sink bubble
                let mut dep_node = SymbolBubble::new(
                    sink_id.clone(),
                    format!("📦 {}", sink_id.split("::").last().unwrap_or(&sink_id)),
                    format!("dependencies/{}", pkg_name),
                    1,
                    SymbolKind::Function,
                    "server".to_string(),
                    "domain".to_string(),
                );
                dep_node.stereotype = "«Vulnerable Dependency»".to_string();
                dep_node.metadata.cve_anomalies.push(anomaly_record);
                graph.nodes.push(dep_node);
            }

            // Connect incoming call edges from application code calling this dependency
            let caller_ids: Vec<String> = graph
                .nodes
                .iter()
                .filter(|n| {
                    !n.id.starts_with("dep::")
                        && !n.id.starts_with("crate::")
                        && n.stereotype != "«Vulnerable Dependency»"
                })
                .filter_map(|node| {
                    let has_matching_call = node.metadata.methods.iter().any(|m| {
                        m.calls
                            .iter()
                            .any(|c| call_matches_target(c, pkg_name, &vuln.affected_functions))
                    });
                    if has_matching_call {
                        Some(node.id.clone())
                    } else {
                        None
                    }
                })
                .collect();

            for caller_id in caller_ids {
                let edge_exists = graph
                    .edges
                    .iter()
                    .any(|e| e.source == caller_id && e.target == sink_id);
                if !edge_exists {
                    graph.edges.push(AffiliationEdge::new(
                        caller_id,
                        sink_id.clone(),
                        EdgeType::Call,
                        FilterAffiliation::PHYSICAL | FilterAffiliation::SEMANTIC,
                    ));
                }
            }
        }
    }

    // 2. Compute reachability across the graph using existing inverse BFS engine
    compute_reachability(graph);

    // 3. Reflect reachability status back into the ScaReport
    let mut reachable_count = 0usize;
    let mut unreachable_count = 0usize;

    for vuln in &mut report.vulnerabilities {
        let mut is_reachable = false;
        let mut exploit_path = Vec::new();

        for node in &graph.nodes {
            for anom in &node.metadata.cve_anomalies {
                if anom.cve_id == vuln.cve_id || anom.rule_id == format!("SCA-{}", vuln.advisory_id) {
                    if anom.is_reachable {
                        is_reachable = true;
                        if exploit_path.is_empty() || anom.exploit_path.len() < exploit_path.len() {
                            exploit_path = anom.exploit_path.clone();
                        }
                    }
                }
            }
        }

        vuln.is_reachable = is_reachable;
        vuln.exploit_path = exploit_path;

        if is_reachable {
            reachable_count += 1;
        } else {
            unreachable_count += 1;
        }
    }

    report.reachable_count = reachable_count;
    report.unreachable_count = unreachable_count;
}
