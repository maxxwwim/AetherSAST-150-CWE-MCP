use crate::dataflow::graph::{DataflowEdge, DataflowGraph};
use crate::dataflow::types::*;
use crate::graph::AetherGraph;
use std::collections::{HashMap, HashSet};

/// Executes dataflow taint propagation across all sources and sinks in the given DataflowGraph.
pub fn execute_track_dataflow(dfg: &DataflowGraph) -> Vec<TaintFlowTrace> {
    let mut traces = Vec::new();

    // Build adjacency map: from scoped_id -> list of edges
    let mut adj: HashMap<String, Vec<&DataflowEdge>> = HashMap::new();
    for edge in &dfg.edges {
        adj.entry(edge.from_var.scoped_id()).or_default().push(edge);
    }

    for source in &dfg.sources {
        for sink in &dfg.sinks {
            // If CWEs are specified, verify compatibility
            if !source.cwe.is_empty() && !sink.cwe.is_empty() && source.cwe != "*" && sink.cwe != "*" {
                if !source.cwe.eq_ignore_ascii_case(&sink.cwe)
                    && !sink.cwe.contains(&source.cwe)
                    && !source.cwe.contains(&sink.cwe)
                {
                    continue;
                }
            }

            // Check if paths exist from source.var to sink.var
            let src_id = source.var.scoped_id();
            let dst_id = sink.var.scoped_id();

            if src_id == dst_id {
                // Direct source is sink (trivial path)
                traces.push(TaintFlowTrace::new(
                    source.clone(),
                    sink.clone(),
                    Vec::new(),
                    false,
                    Vec::new(),
                ));
                continue;
            }

            // Find all simple paths via DFS with cycle detection
            let mut all_paths: Vec<Vec<&DataflowEdge>> = Vec::new();
            let mut current_path: Vec<&DataflowEdge> = Vec::new();
            let mut visited_nodes: HashSet<String> = HashSet::new();
            visited_nodes.insert(src_id.clone());

            find_paths_dfs(
                &src_id,
                &dst_id,
                &adj,
                &mut visited_nodes,
                &mut current_path,
                &mut all_paths,
                32, // maximum recursion depth to prevent infinite expansion
            );

            if all_paths.is_empty() {
                continue;
            }

            // Evaluate each path for sanitization
            let mut unsanitized_path: Option<Vec<&DataflowEdge>> = None;
            let mut shortest_sanitized: Option<(Vec<&DataflowEdge>, Vec<String>)> = None;

            for path in all_paths {
                let mut path_sanitizers = Vec::new();
                let mut path_is_sanitized = false;

                for edge in &path {
                    let mut edge_sanitized = false;
                    let mut sanitizer_name_found = None;

                    // Determine sanitizer name candidate
                    let candidate_name = edge.sanitizer_name.as_deref().or_else(|| match &edge.step_kind {
                        TaintStepKind::SanitizerCall { sanitizer_name, .. } => Some(sanitizer_name.as_str()),
                        _ => None,
                    });

                    if let Some(s_name) = candidate_name {
                        if dfg.is_sanitizer_effective(s_name, &sink.cwe) {
                            edge_sanitized = true;
                            sanitizer_name_found = Some(s_name.to_string());
                        } else if let TaintStepKind::SanitizerCall { ref cwe_targeted, .. } = edge.step_kind {
                            // If not recognized in catalog, check explicit custom cwe_targeted
                            let in_catalog = dfg.sanitizers.iter().any(|r| r.name == s_name);
                            if !in_catalog && (cwe_targeted == "*" || cwe_targeted.eq_ignore_ascii_case(&sink.cwe) || sink.cwe.contains(cwe_targeted)) {
                                edge_sanitized = true;
                                sanitizer_name_found = Some(s_name.to_string());
                            }
                        }
                    } else if edge.is_sanitizer {
                        edge_sanitized = true;
                        sanitizer_name_found = Some("generic_sanitizer".to_string());
                    }

                    if edge_sanitized {
                        path_is_sanitized = true;
                        if let Some(name) = sanitizer_name_found {
                            if !path_sanitizers.contains(&name) {
                                path_sanitizers.push(name);
                            }
                        }
                    }
                }

                if path_is_sanitized {
                    if shortest_sanitized.is_none() || shortest_sanitized.as_ref().map(|(p, _)| p.len()).unwrap_or(0) > path.len() {
                        shortest_sanitized = Some((path, path_sanitizers));
                    }
                } else {
                    // Found an un-sanitized path!
                    if unsanitized_path.is_none() || unsanitized_path.as_ref().map(|p| p.len()).unwrap_or(0) > path.len() {
                        unsanitized_path = Some(path);
                    }
                }
            }

            // If at least one un-sanitized path exists, it is VULNERABLE!
            if let Some(path) = unsanitized_path {
                let steps = edges_to_steps(&path);
                traces.push(TaintFlowTrace::new(
                    source.clone(),
                    sink.clone(),
                    steps,
                    false,
                    Vec::new(),
                ));
            } else if let Some((path, sanitizers_applied)) = shortest_sanitized {
                // All reachable paths are sanitized: NEUTRALIZED!
                let steps = edges_to_steps(&path);
                traces.push(TaintFlowTrace::new(
                    source.clone(),
                    sink.clone(),
                    steps,
                    true,
                    sanitizers_applied,
                ));
            }
        }
    }

    traces
}

/// Helper function to perform depth-bounded DFS finding all simple paths
pub fn find_paths_dfs<'a>(
    current_node: &str,
    target_node: &str,
    adj: &HashMap<String, Vec<&'a DataflowEdge>>,
    visited: &mut HashSet<String>,
    current_path: &mut Vec<&'a DataflowEdge>,
    all_paths: &mut Vec<Vec<&'a DataflowEdge>>,
    max_depth: usize,
) {
    if current_path.len() >= max_depth {
        return;
    }

    if current_node == target_node {
        all_paths.push(current_path.clone());
        return;
    }

    if let Some(out_edges) = adj.get(current_node) {
        for edge in out_edges {
            let next_node = edge.to_var.scoped_id();
            if !visited.contains(&next_node) {
                visited.insert(next_node.clone());
                current_path.push(edge);

                find_paths_dfs(
                    &next_node,
                    target_node,
                    adj,
                    visited,
                    current_path,
                    all_paths,
                    max_depth,
                );

                current_path.pop();
                visited.remove(&next_node);
            }
        }
    }
}

/// Converts a slice of DataflowEdges into 1-indexed TaintStep records
pub fn edges_to_steps(edges: &[&DataflowEdge]) -> Vec<TaintStep> {
    edges
        .iter()
        .enumerate()
        .map(|(idx, edge)| {
            TaintStep::new(
                idx + 1,
                edge.from_var.clone(),
                edge.to_var.clone(),
                edge.step_kind.clone(),
                edge.line,
                edge.is_sanitizer,
                edge.sanitizer_name.clone(),
            )
        })
        .collect()
}

/// Primary public entry point for dataflow taint tracking across sources and sinks.
pub fn track_dataflow(
    graph: &AetherGraph,
    sources: &[TaintSource],
    sinks: &[TaintSink],
    sanitizers: &[SanitizerRule],
) -> Vec<TaintFlowTrace> {
    let mut dfg = if let Some(ref existing) = graph.dataflow_graph {
        existing.clone()
    } else {
        DataflowGraph::new()
    };

    for s in sources {
        dfg.add_source(s.clone());
    }
    for s in sinks {
        dfg.add_sink(s.clone());
    }
    for r in sanitizers {
        dfg.add_sanitizer(r.clone());
    }

    dfg.track_dataflow()
}
