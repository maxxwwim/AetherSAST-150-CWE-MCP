use crate::dataflow::graph::{DataflowEdge, DataflowGraph};
use crate::dataflow::types::*;
use crate::graph::AetherGraph;
use std::collections::{HashMap, HashSet};

/// Executes dataflow taint propagation across all sources and sinks in the given DataflowGraph.
pub fn execute_track_dataflow(dfg: &DataflowGraph) -> Vec<TaintFlowTrace> {
    let mut traces = Vec::new();

    // Build adjacency map: from scoped_id -> list of edges, plus reverse adjacency for O(V+E) reachability pruning
    let mut adj: HashMap<String, Vec<&DataflowEdge>> = HashMap::new();
    let mut rev_adj: HashMap<String, Vec<String>> = HashMap::new();
    for edge in &dfg.edges {
        let from_id = edge.from_var.scoped_id();
        let to_id = edge.to_var.scoped_id();
        adj.entry(from_id.clone()).or_default().push(edge);
        rev_adj.entry(to_id).or_default().push(from_id);
    }

    let mut rev_reach_cache: HashMap<String, HashSet<String>> = HashMap::new();

    for source in &dfg.sources {
        for sink in &dfg.sinks {
            // If CWEs are specified, verify compatibility
            if !cwe_matches(&source.cwe, &sink.cwe) {
                continue;
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

            let can_reach_dst = rev_reach_cache.entry(dst_id.clone()).or_insert_with(|| {
                let mut reached = HashSet::new();
                let mut queue = std::collections::VecDeque::new();
                reached.insert(dst_id.clone());
                queue.push_back((dst_id.clone(), 0usize));
                while let Some((cur, depth)) = queue.pop_front() {
                    if depth >= 32 {
                        continue;
                    }
                    if let Some(preds) = rev_adj.get(&cur) {
                        for pred in preds {
                            if reached.insert(pred.clone()) {
                                queue.push_back((pred.clone(), depth + 1));
                            }
                        }
                    }
                }
                reached
            });

            if !can_reach_dst.contains(&src_id) {
                continue;
            }

            // Find simple paths via DFS with cycle detection and reverse-reachability pruning
            let mut all_paths: Vec<Vec<&DataflowEdge>> = Vec::new();
            let mut current_path: Vec<&DataflowEdge> = Vec::new();
            let mut visited_nodes: HashSet<String> = HashSet::new();
            visited_nodes.insert(src_id.clone());

            find_paths_dfs_pruned(
                &src_id,
                &dst_id,
                &adj,
                can_reach_dst,
                &mut visited_nodes,
                &mut current_path,
                &mut all_paths,
                32, // maximum recursion depth to prevent infinite expansion
                64, // maximum candidate paths per (source, sink) pair
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
                    let candidate_name = edge.sanitizer_name.as_deref().or(match &edge.step_kind {
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
                            if !in_catalog && cwe_matches(cwe_targeted, &sink.cwe) {
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
    if all_paths.len() >= 64 {
        return;
    }

    if current_node == target_node {
        all_paths.push(current_path.clone());
        return;
    }

    if current_path.len() >= max_depth {
        return;
    }

    if let Some(out_edges) = adj.get(current_node) {
        for edge in out_edges {
            if all_paths.len() >= 64 {
                break;
            }
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

#[allow(clippy::too_many_arguments)]
fn find_paths_dfs_pruned<'a>(
    current_node: &str,
    target_node: &str,
    adj: &HashMap<String, Vec<&'a DataflowEdge>>,
    can_reach_dst: &HashSet<String>,
    visited: &mut HashSet<String>,
    current_path: &mut Vec<&'a DataflowEdge>,
    all_paths: &mut Vec<Vec<&'a DataflowEdge>>,
    max_depth: usize,
    max_paths: usize,
) {
    if all_paths.len() >= max_paths {
        return;
    }

    if current_node == target_node {
        all_paths.push(current_path.clone());
        return;
    }

    if current_path.len() >= max_depth {
        return;
    }

    if let Some(out_edges) = adj.get(current_node) {
        for edge in out_edges {
            if all_paths.len() >= max_paths {
                break;
            }
            let next_node = edge.to_var.scoped_id();
            if can_reach_dst.contains(&next_node) && !visited.contains(&next_node) {
                visited.insert(next_node.clone());
                current_path.push(edge);

                find_paths_dfs_pruned(
                    &next_node,
                    target_node,
                    adj,
                    can_reach_dst,
                    visited,
                    current_path,
                    all_paths,
                    max_depth,
                    max_paths,
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
