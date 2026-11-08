pub mod cache;
pub mod cross_ref;
pub mod lockfile;
pub mod osv;

pub use cache::{derive_osv_cache_key, OsvCache, OsvCacheEntry};
pub use cross_ref::cross_reference_reachability;
pub use lockfile::{
    parse_cargo_lock_content, parse_composer_lock_content, parse_lockfile_path,
    parse_package_lock_content, scan_project_lockfiles, ScaDependency,
};
pub use osv::{
    normalize_ecosystem, query_osv, OsvAffected, OsvQueryResponse, OsvReference, OsvSeverity,
    OsvVulnerability,
};

use core_graph::graph::AetherGraph;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// High-level vulnerability finding for a specific software dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaVulnerability {
    pub dependency: ScaDependency,
    pub advisory_id: String,
    pub cve_id: String,
    pub severity: String,
    pub summary: String,
    pub affected_functions: Vec<String>,
    pub is_reachable: bool,
    pub exploit_path: Vec<String>,
    pub remediation: String,
}

/// Consolidated SCA report summarizing dependencies, advisories, and reachability metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScaReport {
    pub project_root: String,
    pub dependencies: Vec<ScaDependency>,
    pub vulnerabilities: Vec<ScaVulnerability>,
    pub reachable_count: usize,
    pub unreachable_count: usize,
    pub total_vulnerabilities: usize,
}

/// Software Composition Analysis Engine
pub struct ScaEngine;

impl ScaEngine {
    /// Scans project lockfiles, interrogates OSV.dev (or local cache), and builds an SCA report
    pub fn scan_project<P: AsRef<Path>>(
        project_root: P,
        offline_only: bool,
    ) -> Result<ScaReport, Box<dyn std::error::Error>> {
        let root = project_root.as_ref();
        let deps = scan_project_lockfiles(root)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let cache = OsvCache::default_for_project(root);
        let mut report = ScaReport {
            project_root: root.to_string_lossy().to_string(),
            dependencies: deps.clone(),
            ..Default::default()
        };

        for dep in &deps {
            if let Ok(vulns) = query_osv(dep, &cache, offline_only) {
                for v in vulns {
                    let cve_id = v.resolve_cve_id();
                    let severity = v.resolve_severity();
                    let affected_fns = v.extract_affected_functions();
                    let summary = v
                        .summary
                        .clone()
                        .unwrap_or_else(|| format!("Vulnerability in {} v{}", dep.name, dep.version));
                    let remediation = format!("Upgrade {} to a secure version", dep.name);

                    report.vulnerabilities.push(ScaVulnerability {
                        dependency: dep.clone(),
                        advisory_id: v.id.clone(),
                        cve_id,
                        severity,
                        summary,
                        affected_functions: affected_fns,
                        is_reachable: false,
                        exploit_path: Vec::new(),
                        remediation,
                    });
                }
            }
        }

        report.total_vulnerabilities = report.vulnerabilities.len();
        report.unreachable_count = report.total_vulnerabilities;
        Ok(report)
    }

    /// Cross-references vulnerable dependencies against the AetherGraph call-graph
    pub fn cross_reference_reachability(graph: &mut AetherGraph, report: &mut ScaReport) {
        cross_reference_reachability(graph, report);
    }
}
