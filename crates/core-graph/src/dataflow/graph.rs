use crate::dataflow::engine::execute_track_dataflow;
use crate::dataflow::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Directed edge in the dataflow propagation graph between two SSA variable instances.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataflowEdge {
    pub from_var: SsaVar,
    pub to_var: SsaVar,
    pub step_kind: TaintStepKind,
    pub line: usize,
    pub is_sanitizer: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitizer_name: Option<String>,
    #[serde(default)]
    pub file_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_snippet: Option<String>,
}

impl DataflowEdge {
    pub fn new(
        from_var: SsaVar,
        to_var: SsaVar,
        step_kind: TaintStepKind,
        line: usize,
        is_sanitizer: bool,
        sanitizer_name: Option<String>,
    ) -> Self {
        let file_path = to_var.file_path.clone().unwrap_or_default();
        Self {
            from_var,
            to_var,
            step_kind,
            line,
            is_sanitizer,
            sanitizer_name,
            file_path,
            code_snippet: None,
        }
    }
}

/// Complete graph of SSA variables, def-use edges, sources, sinks, and sanitizers.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataflowGraph {
    pub nodes: HashMap<String, SsaVar>,
    pub edges: Vec<DataflowEdge>,
    pub sources: Vec<TaintSource>,
    pub sinks: Vec<TaintSink>,
    pub sanitizers: Vec<SanitizerRule>,
}

impl DataflowGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: SanitizerRule::default_catalog(),
        }
    }

    pub fn add_var(&mut self, var: SsaVar) {
        let key = var.scoped_id();
        self.nodes.insert(key, var);
    }

    pub fn add_edge(&mut self, edge: DataflowEdge) {
        self.add_var(edge.from_var.clone());
        self.add_var(edge.to_var.clone());
        self.edges.push(edge);
    }

    pub fn add_source(&mut self, source: TaintSource) {
        self.add_var(source.var.clone());
        self.sources.push(source);
    }

    pub fn add_sink(&mut self, sink: TaintSink) {
        self.add_var(sink.var.clone());
        self.sinks.push(sink);
    }

    pub fn add_sanitizer(&mut self, rule: SanitizerRule) {
        self.sanitizers.push(rule);
    }

    /// Checks if a sanitizer name effectively neutralizes the targeted sink CWE
    pub fn is_sanitizer_effective(&self, sanitizer_name: &str, sink_cwe: &str) -> bool {
        self.sanitizers.iter().any(|r| r.matches(sanitizer_name, sink_cwe))
    }

    /// Executes dataflow taint propagation across all sources and sinks in this graph.
    pub fn track_dataflow(&self) -> Vec<TaintFlowTrace> {
        execute_track_dataflow(self)
    }

    /// Returns only the active vulnerabilities (where is_vulnerable == true, i.e. NOT sanitized).
    pub fn active_vulnerabilities(&self) -> Vec<TaintFlowTrace> {
        self.track_dataflow().into_iter().filter(|t| t.is_vulnerable).collect()
    }
}
