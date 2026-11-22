use core_graph::graph::AetherGraph;
use obsidian_vault::types::DetectedProjectType;
use serde::Serialize;

pub const PHYSICS_WORKER_JS: &str = include_str!("../ui/src/engine/physics.worker.js");
pub const DIST_INDEX_HTML: &str = include_str!("../dist/index.html");

/// Dual-vision graph container serialized for offline standalone bundles.
#[derive(Debug, Clone, Serialize)]
pub struct DualGraphBundle<'a> {
    pub project_type: &'a str,
    pub supported_views: Vec<&'static str>,
    pub active_view: &'a str,
    pub code: Option<&'a AetherGraph>,
    pub vault: Option<&'a AetherGraph>,
}

fn ensure_system_prompt(graph: &AetherGraph) -> AetherGraph {
    let mut graph_clone = graph.clone();
    graph_clone.dataflow_graph = None;
    for n in &mut graph_clone.nodes {
        let is_doc = n.file_path.to_ascii_lowercase().ends_with(".md");
        let is_showcase = n.file_path.starts_with("demo_showcase/");
        if !is_doc && !is_showcase {
            n.metadata.raw_content = None;
        }
        if !n.metadata.cve_anomalies.is_empty() {
            n.metadata.violations.clear();
        }
    }
    if graph_clone.system_prompt.is_none() {
        let p_path = graph_clone
            .project_path
            .as_deref()
            .unwrap_or(&graph_clone.project_name);
        let p_buf = std::path::PathBuf::from(p_path);
        let stack_str = ai_file_bridge::audit_writer::AuditWriter::detect_project_stack(&p_buf);
        let prompt = ai_file_bridge::audit_writer::AuditWriter::generate_optimized_system_prompt(
            &p_buf,
            &graph_clone.project_name,
            stack_str,
            3030,
        );
        graph_clone.system_prompt = Some(prompt);
    }
    graph_clone
}

/// Generates a standalone self-contained HTML bundle embedding both Code and Vault graphs
/// for dual-vision mode when generated from Mixed or single-mode projects.
#[allow(dead_code)]
pub fn generate_dual_standalone_html(
    code_graph: Option<&AetherGraph>,
    vault_graph: Option<&AetherGraph>,
    project_type: DetectedProjectType,
    active_view: &str,
) -> String {
    generate_modern_standalone_html(code_graph, vault_graph, project_type, active_view)
}

fn get_dist_index_html() -> std::borrow::Cow<'static, str> {
    for path in &[
        "crates/desktop-shell/dist/index.html",
        "dist/index.html",
        "../dist/index.html",
    ] {
        if let Ok(content) = std::fs::read_to_string(path) {
            if !content.trim().is_empty() {
                return std::borrow::Cow::Owned(content);
            }
        }
    }
    std::borrow::Cow::Borrowed(DIST_INDEX_HTML)
}

/// Generates a modern Svelte 5 + Vite standalone HTML bundle (ultra-lightweight ~145 KB)
pub fn generate_modern_standalone_html(
    code_graph: Option<&AetherGraph>,
    vault_graph: Option<&AetherGraph>,
    project_type: DetectedProjectType,
    active_view: &str,
) -> String {
    let code_prepared = code_graph.map(ensure_system_prompt);
    let vault_prepared = vault_graph.map(ensure_system_prompt);

    let norm_active = match active_view.trim().to_lowercase().as_str() {
        "vault" | "notes" | "vault-notes" => "vault-notes",
        _ => "code",
    };

    let worker_json = serde_json::to_string(PHYSICS_WORKER_JS)
        .unwrap_or_default()
        .replace("</", "<\\/")
        .replace("<!--", "<\\!--");

    let dual_bundle = DualGraphBundle {
        project_type: project_type.as_str(),
        supported_views: project_type.supported_views(),
        active_view: norm_active,
        code: code_prepared.as_ref(),
        vault: vault_prepared.as_ref(),
    };
    let dual_json = serde_json::to_string(&dual_bundle).unwrap_or_default();
    let safe_dual_json = dual_json
        .replace("</", "<\\/")
        .replace("<!--", "<\\!--");

    let active_key = if norm_active == "vault-notes" { "vault" } else { "code" };
    let injection = format!(
        "<div id=\"view-mode-toggle\" style=\"display:none\" aria-hidden=\"true\">\n\
         <button id=\"btn-view-mode-code\" onclick=\"switchProjectViewMode('code')\"></button>\n\
         <button id=\"btn-view-mode-vault\" onclick=\"switchProjectViewMode('vault-notes')\"></button>\n\
         <button id=\"btn-menu-view-code\" onclick=\"switchProjectViewMode('code')\"></button>\n\
         <button id=\"btn-menu-view-vault\" onclick=\"switchProjectViewMode('vault-notes')\"></button>\n\
         </div>\n\
         <script>\n\
         window.__AETHERSCOPE_DUAL_GRAPH__ = {};\n\
         window.__PHYSICS_WORKER_CODE__ = {};\n\
         window.__AETHERSCOPE_DATA__ = window.__AETHERSCOPE_DUAL_GRAPH__.{} || window.__AETHERSCOPE_DUAL_GRAPH__.code || window.__AETHERSCOPE_DUAL_GRAPH__.vault || {{ project_name: 'AetherScope', nodes: [], edges: [], stats: {{}} }};\n\
         window.AETHER_GRAPH_DATA = window.__AETHERSCOPE_DATA__;\n\
         window.AETHER_DUAL_GRAPH = window.__AETHERSCOPE_DUAL_GRAPH__;\n\
         async function switchProjectViewMode(mode) {{\n\
             if (window.__AETHERSCOPE_DUAL_GRAPH__ && window.__AETHERSCOPE_DUAL_GRAPH__[mode]) {{\n\
                 window.__AETHERSCOPE_DATA__ = window.__AETHERSCOPE_DUAL_GRAPH__[mode];\n\
                 window.AETHER_GRAPH_DATA = window.__AETHERSCOPE_DATA__;\n\
                 if (window.dispatchEvent) {{\n\
                     window.dispatchEvent(new CustomEvent('aether:viewmode', {{ detail: mode }}));\n\
                 }}\n\
             }}\n\
         }}\n\
         async function fetchProjectStatus() {{\n\
             return {{ project_type: window.__AETHERSCOPE_DUAL_GRAPH__?.project_type || 'Mixed' }};\n\
         }}\n\
         </script>",
        safe_dual_json, worker_json, active_key
    );

    let dist_html = get_dist_index_html();
    if let Some(pos) = dist_html.rfind("<div id=\"app\"></div>") {
        let mut out = String::with_capacity(dist_html.len() + injection.len() + 16);
        out.push_str(&dist_html[..pos]);
        out.push_str(&injection);
        out.push_str("\n    ");
        out.push_str(&dist_html[pos..]);
        out
    } else if let Some(pos) = dist_html.rfind("<body") {
        let mut out = String::with_capacity(dist_html.len() + injection.len() + 16);
        out.push_str(&dist_html[..pos]);
        out.push_str(&injection);
        out.push('\n');
        out.push_str(&dist_html[pos..]);
        out
    } else {
        format!("{}\n{}", injection, dist_html)
    }
}

/// Backward compatible generator for single graph export.
#[allow(dead_code)]
pub fn generate_standalone_html(graph: &AetherGraph) -> String {
    generate_dual_standalone_html(
        Some(graph),
        None,
        DetectedProjectType::PureCode,
        "code",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_graph::bubble::{SymbolBubble, SymbolKind};

    #[test]
    fn test_generate_standalone_html() {
        let graph = AetherGraph::new("TestProject");
        let html = generate_standalone_html(&graph);

        assert!(html.contains("<!doctype html>") || html.contains("<!DOCTYPE html>"));
        assert!(html.contains("window.__AETHERSCOPE_DATA__"));
        assert!(html.contains("window.__AETHERSCOPE_DUAL_GRAPH__"));
        assert!(html.contains("window.AETHER_GRAPH_DATA"));
        assert!(html.contains("window.AETHER_DUAL_GRAPH"));
        assert!(html.contains("window.__PHYSICS_WORKER_CODE__"));
        assert!(html.contains("system_prompt"));
        assert!(html.contains("aether-canvas") || html.contains("AetherScope") || html.contains("physics_worker"));
        assert!(!html.contains("src=\"app.js\""));
        assert!(!html.contains("src=\"state_api.js\""));
        assert!(!html.contains("href=\"styles.css\""));
        assert!(html.len() > 50_000);
    }

    #[test]
    fn test_generate_modern_standalone_html() {
        let graph = AetherGraph::new("ModernProject");
        let html = generate_modern_standalone_html(
            Some(&graph),
            None,
            DetectedProjectType::PureCode,
            "code",
        );

        assert!(html.contains("window.__AETHERSCOPE_DATA__"));
        assert!(html.contains("window.__AETHERSCOPE_DUAL_GRAPH__"));
        assert!(html.contains("window.AETHER_GRAPH_DATA"));
        assert!(html.contains("aether-canvas"));
        assert_eq!(html.matches("<div id=\"view-mode-toggle\"").count(), 1);
        assert_eq!(html.matches("window.__AETHERSCOPE_DUAL_GRAPH__ =").count(), 1);
        assert!(html.len() > 50_000);
    }

    #[test]
    fn test_generate_dual_standalone_html_mixed() {
        let mut code_graph = AetherGraph::new("MixedCodeProject");
        code_graph.add_node(SymbolBubble::new(
            "crates/core/src/main.rs::run".to_string(),
            "run".to_string(),
            "crates/core/src/main.rs".to_string(),
            10,
            SymbolKind::Function,
            "server".to_string(),
            "domain".to_string(),
        ));

        let mut vault_graph = AetherGraph::new("MixedVaultNotes");
        vault_graph.add_node(SymbolBubble::new(
            "note::Architecture".to_string(),
            "Architecture".to_string(),
            "notes/Architecture.md".to_string(),
            1,
            SymbolKind::File,
            "contracts".to_string(),
            "docs".to_string(),
        ));

        let html = generate_dual_standalone_html(
            Some(&code_graph),
            Some(&vault_graph),
            DetectedProjectType::Mixed,
            "code",
        );

        assert!(html.contains("window.__AETHERSCOPE_DATA__"));
        assert!(html.contains("window.__AETHERSCOPE_DUAL_GRAPH__"));
        assert!(html.contains("window.AETHER_DUAL_GRAPH"));
        assert!(html.contains("\"project_type\":\"Mixed\""));
        assert!(html.contains("\"supported_views\":[\"code\",\"vault-notes\"]"));
        assert!(html.contains("\"active_view\":\"code\""));
        assert!(html.contains("crates/core/src/main.rs::run"));
        assert!(html.contains("note::Architecture"));
    }

    #[test]
    fn test_generate_dual_standalone_html_vault_active() {
        let mut vault_graph = AetherGraph::new("PureVaultProject");
        vault_graph.add_node(SymbolBubble::new(
            "note::Index".to_string(),
            "Index".to_string(),
            "Index.md".to_string(),
            1,
            SymbolKind::File,
            "contracts".to_string(),
            "docs".to_string(),
        ));

        let html = generate_dual_standalone_html(
            None,
            Some(&vault_graph),
            DetectedProjectType::PureObsidianVault,
            "vault-notes",
        );

        assert!(html.contains("window.__AETHERSCOPE_DATA__"));
        assert!(html.contains("\"project_type\":\"PureObsidianVault\""));
        assert!(html.contains("\"supported_views\":[\"vault-notes\",\"code\"]"));
        assert!(html.contains("\"active_view\":\"vault-notes\""));
        assert!(html.contains("note::Index"));
    }

    #[test]
    fn test_generate_dual_standalone_html_pure_code() {
        let mut code_graph = AetherGraph::new("PureCodeProject");
        code_graph.add_node(SymbolBubble::new(
            "src/lib.rs::compute".to_string(),
            "compute".to_string(),
            "src/lib.rs".to_string(),
            5,
            SymbolKind::Function,
            "server".to_string(),
            "domain".to_string(),
        ));

        let html = generate_dual_standalone_html(
            Some(&code_graph),
            None,
            DetectedProjectType::PureCode,
            "code",
        );

        assert!(html.contains("\"project_type\":\"PureCode\""));
        assert!(html.contains("\"supported_views\":[\"code\"]"));
        assert!(html.contains("\"vault\":null"));
        assert!(html.contains("src/lib.rs::compute"));
    }

    fn build_demo_showcase_graph() -> AetherGraph {
        let tmp = tempfile::tempdir().expect("create temp dir for demo showcase");
        let showcase_dir = tmp.path().join("demo_showcase");
        std::fs::create_dir_all(&showcase_dir).expect("create demo_showcase dir");

        let demo_readme = r#"---
id: demo_showcase
layer: domain
max_lines_per_file: 120
forbidden_imports: ["std::process::Command"]
forbidden_functions: ["eval"]
security_rules:
  no_raw_sql: true
  no_env_access: false
  untrusted_client_input: true
---
# 🧪 Demo Showcase — Live SAST, SSA Taint & CWE Arena

Interactive vulnerable polyglot sandbox (**TypeScript**, **Python**, **Rust**) embedded exclusively in the standalone GitHub Pages demo (`docs/index.html`) so visitors can explore live **CWE red beacons**, **SSA Taint source→sink traces**, **exploit reachability paths**, and **BLAKE3 contract violations** — while `aether-engine` itself remains **0-violation clean** on self-audit.

## 🎯 Included Live Vulnerabilities
- **TypeScript (`auth_controller.ts`)**: SQL Injection (`CWE-89`), OS Command Injection (`CWE-78`), Dynamic Code Eval (`CWE-94` + `RULE_FORBIDDEN_FUNCTION`), DOM XSS (`CWE-79`), Prototype Pollution (`CWE-1321`).
- **Python (`payment_gateway.py`)**: Insecure Deserialization (`CWE-502`), Command Injection (`CWE-78`), SQL Injection (`CWE-89`), Path Traversal (`CWE-22`), Weak Crypto MD5 (`CWE-328`).
- **Rust (`vault_bridge.rs`)**: Forbidden Import (`RULE_FORBIDDEN_IMPORT`), Unsafe Transmute (`CWE-119`), Command Injection (`CWE-78`), Path Join Prefix Wipe (`AETHER-PATH-008`), Async Mutex across `.await`.
"#;

        let auth_ts = r#"import express from 'express';
import { exec } from 'child_process';

const app = express();

export function lookupUserByEmail(db: any, email: string) {
    const sql = "SELECT id, role FROM users WHERE email = '" + email + "'";
    return db.query(sql);
}

export function runDiagnosticPing(host: string) {
    return exec("ping -c 1 " + host);
}

export function evaluatePricingFormula(formula: string) {
    return eval(formula);
}

export function renderWelcomeBanner(req: any, container: HTMLElement) {
    const bannerHtml = req.query.banner;
    const markup = "<div>" + bannerHtml + "</div>";
    container.innerHTML = markup;
}

export function searchAuditLogs(req: any, db: any) {
    const rawQuery = req.query.search;
    const sql = "SELECT id, event FROM audit_logs WHERE msg = '" + rawQuery + "'";
    return db.query(sql);
}

export function mergeUserProfile(req: any, target: Record<string, any>) {
    const payload: any = req.body;
    return Object.assign(target, payload);
}

app.post('/api/demo/auth/login', (req: any, res: any) => {
    const email = req.query.email;
    const host = req.query.host;
    const formula = req.body.formula;
    lookupUserByEmail(req.app.locals.db, email);
    searchAuditLogs(req, req.app.locals.db);
    runDiagnosticPing(host);
    const price = evaluatePricingFormula(formula);
    mergeUserProfile(req, {});
    res.send(req.query.banner + String(price));
});
"#;

        let payment_py = r#"import hashlib
import pickle
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

def fetch_invoice(conn, invoice_id):
    cursor = conn.cursor()
    query = "SELECT * FROM invoices WHERE ref = '" + invoice_id + "'"
    return cursor.execute(query).fetchall()

def deserialize_receipt(raw_blob):
    return pickle.loads(raw_blob)

def dispatch_webhook(callback_url):
    return subprocess.Popen("curl -s " + callback_url, shell=True)

def read_statement_pdf(filename):
    with open("/var/billing/statements/" + filename, "rb") as handle:
        return handle.read()

def hash_pin_legacy(pin_code):
    return hashlib.md5(pin_code.encode("utf-8")).hexdigest()

@app.route('/api/demo/payments/process', methods=['POST'])
def process_payment():
    invoice_id = request.args.get("invoice_id", "")
    callback_url = request.args.get("callback", "")
    filename = request.args.get("file", "")
    conn = sqlite3.connect(":memory:")
    fetch_invoice(conn, invoice_id)
    deserialize_receipt(request.data)
    dispatch_webhook(callback_url)
    read_statement_pdf(filename)
    return hash_pin_legacy(request.form.get("pin", ""))
"#;

        let vault_rs = r#"use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

pub fn execute_vault_hook(user_cmd: &str) -> std::io::Result<std::process::Output> {
    Command::new("sh").arg("-c").arg(user_cmd).output()
}

pub fn resolve_vault_export(base_dir: &PathBuf, user_rel_path: &str) -> PathBuf {
    base_dir.join(user_rel_path)
}

pub fn read_raw_slot(raw_addr: u64) -> *const u8 {
    unsafe { std::mem::transmute::<u64, *const u8>(raw_addr) }
}

pub async fn sync_vault_state(shared_lock: &Mutex<String>) {
    let mut guard = shared_lock.lock().unwrap();
    guard.push_str("syncing");
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
}
"#;

        std::fs::write(showcase_dir.join("README.md"), demo_readme).unwrap();
        std::fs::write(showcase_dir.join("auth_controller.ts"), auth_ts).unwrap();
        std::fs::write(showcase_dir.join("payment_gateway.py"), payment_py).unwrap();
        std::fs::write(showcase_dir.join("vault_bridge.rs"), vault_rs).unwrap();

        let scanner = ast_scanner::scanner::ProjectScanner::default();
        scanner.scan_project(tmp.path())
    }

    #[test]
    fn test_export_docs_index_html() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = std::fs::canonicalize(manifest_dir.join("../..")).unwrap();
        let scanner = ast_scanner::scanner::ProjectScanner::default();
        let mut code_graph = scanner.scan_project(&root);

        // Merge isolated polyglot CWE/Taint showcase strictly into the standalone demo export
        // so visitors see live CWE beacons, SSA taint flows & contract alerts while keeping
        // the real `aether-engine` repository at 0 violations.
        let showcase_graph = build_demo_showcase_graph();
        let existing_ids: std::collections::HashSet<String> =
            code_graph.nodes.iter().map(|n| n.id.clone()).collect();
        let (max_x, min_y) = code_graph.nodes.iter().fold((0.0f64, 0.0f64), |(mx, my), n| {
            (mx.max(n.x), my.min(n.y))
        });
        let offset_x = max_x + 900.0;
        let offset_y = min_y + 400.0;

        let mut added_nodes = 0usize;
        for mut node in showcase_graph.nodes {
            if existing_ids.contains(&node.id) {
                continue;
            }
            node.x += offset_x;
            node.y += offset_y;
            for pt in [
                node.layouts.obsidian.as_mut(),
                node.layouts.system.as_mut(),
                node.layouts.flow.as_mut(),
                node.layouts.classes.as_mut(),
            ]
            .into_iter()
            .flatten()
            {
                pt.x += offset_x;
                pt.y += offset_y;
            }
            code_graph.nodes.push(node);
            added_nodes += 1;
        }
        code_graph.edges.extend(showcase_graph.edges);
        code_graph.stats.files_scanned += showcase_graph.stats.files_scanned;
        code_graph.compute_stats();

        println!(
            "Exporting docs/index.html for root: {:?}, nodes: {} (+{} demo_showcase), violations: {}",
            root,
            code_graph.nodes.len(),
            added_nodes,
            code_graph.stats.violation_count
        );
        assert!(code_graph.nodes.len() > 50, "Graph must contain nodes!");
        assert!(
            code_graph.stats.violation_count > 0,
            "Standalone demo must expose live demo_showcase CWE findings!"
        );

        let detection_report = obsidian_vault::detect_project_type(&root).ok();
        let project_type = detection_report
            .as_ref()
            .map(|r| r.project_type)
            .unwrap_or(obsidian_vault::DetectedProjectType::PureCode);
        let active_view_mode = detection_report
            .as_ref()
            .map(|r| r.default_view.clone())
            .unwrap_or_else(|| "code".to_string());

        let vault_graph = if project_type.is_vault() || project_type.is_mixed() {
            obsidian_vault::scan_obsidian_vault(&root).ok()
        } else {
            None
        };

        let html = generate_dual_standalone_html(
            Some(&code_graph),
            vault_graph.as_ref(),
            project_type,
            &active_view_mode,
        );
        let docs_path = root.join("docs/index.html");
        let _ = std::fs::write(&docs_path, &html);
        assert!(html.contains("window.__AETHERSCOPE_DATA__"));
        assert!(html.contains("system_prompt"));
        assert!(html.contains("window.__AETHERSCOPE_DUAL_GRAPH__"));
    }
}
