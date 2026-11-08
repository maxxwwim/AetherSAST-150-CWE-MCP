use crate::bubble::SymbolBubble;
use crate::edge::{AffiliationEdge, FilterAffiliation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    #[serde(default)]
    pub files_scanned: usize,
    pub rpc_count: usize,
    pub realtime_count: usize,
    pub violation_count: usize,
    pub dead_code_count: usize,
    #[serde(default)]
    pub elapsed_ms: u128,
    #[serde(default)]
    pub layers: HashMap<String, usize>,
    #[serde(default)]
    pub relations: HashMap<String, usize>,
    #[serde(default)]
    pub sides: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AetherGraph {
    pub project_name: String,
    #[serde(default)]
    pub project_path: Option<String>,
    #[serde(default)]
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    pub nodes: Vec<SymbolBubble>,
    pub edges: Vec<AffiliationEdge>,
    pub stats: GraphStats,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataflow_graph: Option<crate::dataflow::DataflowGraph>,
}

impl AetherGraph {
    pub fn new(project_name: &str) -> Self {
        let dur = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            project_name: project_name.to_string(),
            project_path: None,
            generated_at: format!("Unix: {}s", dur.as_secs()),
            system_prompt: None,
            nodes: Vec::new(),
            edges: Vec::new(),
            stats: GraphStats::default(),
            dataflow_graph: None,
        }
    }

    pub fn add_node(&mut self, node: SymbolBubble) {
        self.nodes.push(node);
    }

    pub fn add_edge(&mut self, edge: AffiliationEdge) {
        self.edges.push(edge);
    }

    pub fn compute_reachability(&mut self) {
        crate::reachability::compute_reachability(self);
    }

    /// Evaluates SSA dataflow taint propagation across sources and sinks.
    /// Neutralizes anomalies when is_sanitized == true, or equips them with exact TaintFlowTrace when unsanitized.
    pub fn compute_dataflow_taint(&mut self, custom_sanitizers: &[crate::dataflow::SanitizerRule]) -> Vec<crate::dataflow::TaintFlowTrace> {
        let traces = if let Some(ref mut dfg) = self.dataflow_graph {
            for s in custom_sanitizers {
                dfg.add_sanitizer(s.clone());
            }
            dfg.track_dataflow()
        } else {
            Vec::new()
        };

        for trace in &traces {
            let sink_file = &trace.sink.file_path;
            let sink_line = trace.sink.line;
            let sink_var = &trace.sink.var.name;

            for node in &mut self.nodes {
                for anom in &mut node.metadata.cve_anomalies {
                    let matches_loc = (anom.file_path == *sink_file && anom.line_number == sink_line)
                        || (anom.line_number == sink_line && (anom.file_path.ends_with(sink_file) || sink_file.ends_with(&anom.file_path)))
                        || (anom.cve_id.contains(&trace.sink.cwe) && anom.line_number == sink_line)
                        || (anom.transmitted_data.as_deref() == Some(sink_var) && anom.cve_id.contains(&trace.sink.cwe));

                    if matches_loc {
                        anom.taint_trace = Some(trace.clone());
                        if trace.is_sanitized {
                            anom.is_reachable = false;
                        } else {
                            anom.is_reachable = true;
                        }
                    }
                }

                if !node.metadata.cve_anomalies.is_empty()
                    && node.metadata.cve_anomalies.iter().all(|a| !a.is_reachable)
                {
                    node.has_security_violation = false;
                }
            }
        }

        traces
    }

    pub fn compute_stats(&mut self) {
        self.compute_reachability();

        let mut rpc = 0;
        let mut realtime = 0;
        let mut violations = 0;
        let mut relations: HashMap<String, usize> = HashMap::new();

        for e in &self.edges {
            *relations.entry(e.relation.clone()).or_insert(0) += 1;
            if e.filters.contains(FilterAffiliation::NETWORK_RPC) {
                rpc += 1;
            }
            if e.filters.contains(FilterAffiliation::REALTIME_WS) {
                realtime += 1;
            }
            if e.filters.contains(FilterAffiliation::SECURITY_VIOLATES) {
                violations += 1;
            }
        }

        // Calcule in-degree et out-degree pour chaque noeud
        let mut in_degrees: HashMap<&str, usize> = HashMap::new();
        let mut out_degrees: HashMap<&str, usize> = HashMap::new();
        for e in &self.edges {
            *in_degrees.entry(&e.target).or_default() += 1;
            *out_degrees.entry(&e.source).or_default() += 1;
        }

        let mut dead_code = 0;
        let mut files_scanned = 0;
        let mut node_violations = 0;
        let mut layers: HashMap<String, usize> = HashMap::new();
        let mut sides: HashMap<String, usize> = HashMap::new();

        for n in &mut self.nodes {
            if n.is_file {
                files_scanned += 1;
            }
            if n.has_security_violation {
                node_violations += 1;
            }
            *layers.entry(n.layer.clone()).or_insert(0) += 1;
            *sides.entry(n.side.clone()).or_insert(0) += 1;

            let in_deg = in_degrees.get(n.id.as_str()).copied().unwrap_or(0);
            let out_deg = out_degrees.get(n.id.as_str()).copied().unwrap_or(0);
            n.in_degree = in_deg;
            n.out_degree = out_deg;

            if n.layer != "ui" && n.layer != "docs" && in_deg == 0 {
                n.is_dead_code = true;
                dead_code += 1;
            } else {
                n.is_dead_code = false;
            }
        }

        self.stats = GraphStats {
            total_nodes: self.nodes.len(),
            total_edges: self.edges.len(),
            files_scanned: if self.stats.files_scanned > 0 {
                self.stats.files_scanned
            } else {
                files_scanned
            },
            rpc_count: rpc,
            realtime_count: realtime,
            violation_count: violations.max(node_violations),
            dead_code_count: dead_code,
            elapsed_ms: self.stats.elapsed_ms,
            layers,
            relations,
            sides,
        };
    }
}
