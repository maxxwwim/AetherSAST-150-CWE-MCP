use crate::bubble::{SymbolBubble, SymbolKind};
use crate::edge::FilterAffiliation;
use crate::graph::AetherGraph;
use std::collections::{HashMap, VecDeque};

/// Checks if a node qualifies as a public entrypoint (Source).
pub fn is_source_node(node: &SymbolBubble) -> bool {
    node.kind == SymbolKind::FormOrEndpoint
        || node.stereotype.contains("Endpoint")
        || node.stereotype.contains("Form")
        || node.id.starts_with("api::")
}

/// Computes backward reachability from all CVE anomaly sinks to public sources.
///
/// For each bubble containing one or more `CveAnomalyRecord` entries (Sink),
/// this performs an inverse BFS traversing incoming edges matching:
/// `FilterAffiliation::NETWORK_RPC | FilterAffiliation::REALTIME_WS | FilterAffiliation::SEMANTIC`.
///
/// If a continuous path exists from an external/public source node (`SymbolKind::FormOrEndpoint`),
/// the shortest path is reconstructed in forward execution order:
/// `Endpoint -> Handler -> Service -> Sink`
/// and stored in `exploit_path`, with `is_reachable = true`.
/// If no path exists, `is_reachable = false` and `exploit_path` is cleared.
pub fn compute_reachability(graph: &mut AetherGraph) {
    if graph.nodes.is_empty() {
        return;
    }

    // 1. Build index from node.id -> index in graph.nodes
    let mut node_idx_map: HashMap<&str, usize> = HashMap::with_capacity(graph.nodes.len());
    let mut is_source: Vec<bool> = vec![false; graph.nodes.len()];
    let mut sink_node_indices: Vec<usize> = Vec::new();

    for (idx, node) in graph.nodes.iter().enumerate() {
        node_idx_map.insert(&node.id, idx);
        if is_source_node(node) {
            is_source[idx] = true;
        }
        if !node.metadata.cve_anomalies.is_empty() {
            sink_node_indices.push(idx);
        }
    }

    if sink_node_indices.is_empty() {
        return;
    }

    // 2. Pre-filter incoming execution edges matching allowed filters
    let allowed_filters = FilterAffiliation::NETWORK_RPC
        | FilterAffiliation::REALTIME_WS
        | FilterAffiliation::SEMANTIC;

    let mut incoming_adj: Vec<Vec<usize>> = vec![Vec::new(); graph.nodes.len()];
    for edge in &graph.edges {
        if edge.filters.intersects(allowed_filters) {
            if let (Some(&src_idx), Some(&tgt_idx)) = (
                node_idx_map.get(edge.source.as_str()),
                node_idx_map.get(edge.target.as_str()),
            ) {
                if src_idx != tgt_idx {
                    incoming_adj[tgt_idx].push(src_idx);
                }
            }
        }
    }

    // 3. Run inverse BFS for each sink node
    for sink_idx in sink_node_indices {
        // Trivial case: Sink is itself a public source
        if is_source[sink_idx] {
            let sink_id = graph.nodes[sink_idx].id.clone();
            for anom in &mut graph.nodes[sink_idx].metadata.cve_anomalies {
                anom.is_reachable = true;
                anom.exploit_path = vec![sink_id.clone()];
            }
            continue;
        }

        let mut queue: VecDeque<usize> = VecDeque::new();
        let mut visited: Vec<bool> = vec![false; graph.nodes.len()];
        // forward_next[prev] = Some(curr) points in the forward (execution) direction
        let mut forward_next: Vec<Option<usize>> = vec![None; graph.nodes.len()];

        queue.push_back(sink_idx);
        visited[sink_idx] = true;

        let mut found_source: Option<usize> = None;

        while let Some(curr) = queue.pop_front() {
            if is_source[curr] {
                found_source = Some(curr);
                break;
            }

            for &prev in &incoming_adj[curr] {
                if !visited[prev] {
                    visited[prev] = true;
                    // prev calls curr, so forward direction from prev is curr
                    forward_next[prev] = Some(curr);
                    queue.push_back(prev);
                }
            }
        }

        if let Some(src_idx) = found_source {
            // Reconstruct forward path from Source -> ... -> Sink
            let mut path_indices: Vec<usize> = Vec::new();
            let mut curr = src_idx;
            path_indices.push(curr);

            while curr != sink_idx {
                if let Some(next_hop) = forward_next[curr] {
                    path_indices.push(next_hop);
                    curr = next_hop;
                } else {
                    break;
                }
            }

            let exploit_path: Vec<String> = path_indices
                .into_iter()
                .map(|idx| graph.nodes[idx].id.clone())
                .collect();

            for anom in &mut graph.nodes[sink_idx].metadata.cve_anomalies {
                anom.is_reachable = true;
                anom.exploit_path = exploit_path.clone();
            }
        } else {
            for anom in &mut graph.nodes[sink_idx].metadata.cve_anomalies {
                anom.is_reachable = false;
                anom.exploit_path.clear();
            }
        }
    }
}
