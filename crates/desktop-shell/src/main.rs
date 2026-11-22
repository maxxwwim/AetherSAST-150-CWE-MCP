#![windows_subsystem = "windows"]
#![recursion_limit = "512"]

mod api_routes;
mod benchmark;
mod local_guard;
mod mcp;
mod plugin_routes;
mod surface_scanner;
mod viewer;
mod visual_plugin_routes;

use api_routes::*;
use ai_file_bridge::{AuditWriter, FileWatcherBridge, HandshakePacker};
use ast_scanner::ProjectScanner;
use clap::Parser;
use security_linter::contract::ReadmeContract;
use security_linter::{SecretGuard, SecretMasker};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use obsidian_vault::{PathGuard, SecurityError};

use tao::{
    dpi::LogicalSize,
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "AetherScope V2 - Autonomous Graph Engine, SAST & AI Guardrail Bridge", long_about = None)]
pub struct Args {
    #[arg(short, long, default_value = ".")]
    pub path: String,

    #[arg(long, default_value_t = 3030)]
    pub port: u16,

    #[arg(long, default_value_t = false)]
    pub audit_only: bool,

    #[arg(long, default_value_t = false)]
    pub no_gui: bool,

    #[arg(long, default_value_t = false)]
    pub mcp: bool,

    /// Output format for SAST audit: "text", "markdown", or "sarif"
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Path to export report file (e.g. "report.sarif")
    #[arg(short, long)]
    pub output: Option<String>,

    /// Block and exit with code 1 if findings meet or exceed severity ("CRITICAL" or "HIGH")
    #[arg(long)]
    pub fail_on: Option<String>,

    #[arg(long, help = "Run benchmark measuring lexing, AST, SAST evaluation, peak RSS and LOC/s throughput")]
    pub benchmark: bool,

    /// Update and hydrate Semgrep community rules bundle into .aether/plugins/
    #[arg(long, default_value_t = false)]
    pub update_rules: bool,

    /// Enable Software Composition Analysis (SCA) dependency vulnerability scanning
    #[arg(long, default_value_t = false)]
    pub sca: bool,

    /// Force 100% offline SCA scanning (use local disk cache only)
    #[arg(long, default_value_t = false)]
    pub offline_sca: bool,

    /// Run only SCA audit and output results
    #[arg(long, default_value_t = false)]
    pub sca_only: bool,

    /// Select active SAST plugin packs or profiles: "auto", "all", "<pack1>,<pack2>", or "profile:<name>"
    #[arg(long, value_name = "SPEC")]
    pub plugins: Option<String>,
}

fn resolve_scanner_for_args(
    project_root: &Path,
    plugins_arg: Option<&str>,
) -> Result<(ProjectScanner, security_linter::PluginEngine), String> {
    let selection = match plugins_arg {
        Some(s) => security_linter::PluginSelection::parse(s)?,
        None => security_linter::PluginSelection::Default,
    };
    let scanner = ProjectScanner::default().with_plugin_selection(selection);
    let engine = scanner.validate_plugins(project_root)?;
    Ok((scanner, engine))
}


#[cfg(windows)]
extern "system" {
    fn AttachConsole(dw_process_id: u32) -> i32;
}

fn main() {
    #[cfg(windows)]
    unsafe {
        AttachConsole(0xFFFF_FFFF);
    }
    std::panic::set_hook(Box::new(|info| {
        let _ = std::fs::write("desktop-shell-panic.log", format!("PANIC: {:?}", info));
    }));
    if let Err(e) = real_main() {
        let _ = std::fs::write("desktop-shell-error.log", format!("MAIN ERROR: {:?}", e));
    }
}

/// Maps a `SecurityError` from `PathGuard` to the appropriate HTTP status code and JSON error payload.
fn security_error_to_status_and_json(err: &SecurityError) -> (axum::http::StatusCode, serde_json::Value) {
    use axum::http::StatusCode;
    match err {
        SecurityError::NullByteDetected(_)
        | SecurityError::PathTraversal(_)
        | SecurityError::UncPathProhibited(_)
        | SecurityError::DriveLetterProhibited(_)
        | SecurityError::AbsolutePathsProhibited(_)
        | SecurityError::UrlSchemeProhibited(_)
        | SecurityError::InvalidPrefix(_)
        | SecurityError::DepthExceeded { .. }
        | SecurityError::ExtensionNotAllowed { .. }
        | SecurityError::NotAFile(_) => (
            StatusCode::BAD_REQUEST,
            serde_json::json!({
                "status": "error",
                "error": "bad_request",
                "message": err.to_string(),
            }),
        ),
        SecurityError::SensitiveFileProhibited(_)
        | SecurityError::PathEscapesRoot { .. }
        | SecurityError::SymlinkEscape { .. }
        | SecurityError::SymlinksDisabled(_) => (
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "status": "error",
                "error": "forbidden",
                "message": err.to_string(),
            }),
        ),
        SecurityError::FileTooLarge { .. } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            serde_json::json!({
                "status": "error",
                "error": "payload_too_large",
                "message": err.to_string(),
            }),
        ),
        SecurityError::IoError { source, .. } if source.kind() == std::io::ErrorKind::NotFound => (
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "status": "error",
                "error": "not_found",
                "message": err.to_string(),
            }),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({
                "status": "error",
                "error": "internal_error",
                "message": err.to_string(),
            }),
        ),
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.update_rules {
        let plugins_dir = Path::new(&args.path).join(".aether").join("plugins");
        println!("ðŸ”„ Synchronizing Semgrep community rules bundle to {}", plugins_dir.display());
        match security_linter::CommunityBundle::unpack_to_directory(&plugins_dir) {
            Ok(p) => {
                println!("âœ… Successfully hydrated Semgrep community bundle at {}", p.display());
            }
            Err(e) => {
                eprintln!("âŒ Failed to hydrate Semgrep community rules: {}", e);
                return Err(Box::new(e));
            }
        }
        if args.no_gui || (!args.audit_only && !std::env::args().any(|a| a == "--port" || a == "--mcp")) {
            return Ok(());
        }
    }

    if args.benchmark {
        if let Err(e) = benchmark::run_benchmark_with_plugins(&args.path, args.plugins.as_deref()) {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
        return Ok(());
    }

    let port = args.port;
    let audit_only = args.audit_only;
    let no_gui = args.no_gui;
    let mcp = args.mcp;

    if mcp {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(async move {
            if !mcp::check_server_listening(port) {
                let server_args = args.clone();
                tokio::spawn(async move {
                    let _ = run_server_and_watcher(server_args).await;
                });
                tokio::time::sleep(tokio::time::Duration::from_millis(350)).await;
            }
            mcp::run_mcp_stdio_loop(port, &args.path).await
        });
    }

    if args.sca_only {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(run_sca_only_cli(args));
    }

    if audit_only || args.format.eq_ignore_ascii_case("sarif") || args.fail_on.is_some() || args.sca || args.offline_sca {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(run_audit_cli(args));
    }

    // DÃ©marre le serveur backend Axum et le File-Watcher dans un thread d'arriÃ¨re-plan Tokio
    let server_args = args.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("Ã‰chec initialisation Tokio runtime");
        rt.block_on(async {
            if let Err(e) = run_server_and_watcher(server_args).await {
                let _ = std::fs::write("server-error.log", format!("SERVER ERROR: {:?}", e));
                eprintln!("âš ï¸ Erreur serveur interne : {}", e);
            }
        });
    });

    if no_gui {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    // =========================================================================
    // NATIVE DESKTOP WINDOW (FULL IN-EXE GUI VIA TAO + WRY / TAURI ENGINE)
    // =========================================================================
    std::thread::sleep(std::time::Duration::from_millis(350));

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("ðŸª AetherScope V2 â€” Architectural Intelligence & Live GPU Cockpit")
        .with_maximized(true)
        .with_inner_size(LogicalSize::new(1280.0, 800.0))
        .with_min_inner_size(LogicalSize::new(800.0, 500.0))
        .build(&event_loop)?;

    let app_url = format!("http://127.0.0.1:{}", port);
    // Budget mémoire WebView2 : jusqu'à 4 Go de tas JS (défaut V8 ~1,4-2 Go => saccades/GC
    // permanents puis crash sur les gros graphes) + conservation des flags wry par défaut.
    #[cfg(windows)]
    let webview_builder = {
        use wry::WebViewBuilderExtWindows;
        WebViewBuilder::new(&window).with_additional_browser_args(
            "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection \
             --js-flags=--max-old-space-size=4096",
        )
    };
    #[cfg(not(windows))]
    let webview_builder = WebViewBuilder::new(&window);
    let _webview = webview_builder
        .with_url(&app_url)
        .with_devtools(true)
        .build()?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {}
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }
            _ => (),
        }
    });
}

pub(crate) fn extract_live_audit_from_graph(
    graph: &core_graph::graph::AetherGraph,
) -> (Vec<security_linter::linter::LinterViolation>, usize) {
    let mut violations = Vec::new();
    let mut file_count = 0usize;
    for node in &graph.nodes {
        if node.kind == core_graph::bubble::SymbolKind::File {
            file_count += 1;
        }
        for rec in &node.metadata.cve_anomalies {
            violations.push(security_linter::linter::LinterViolation {
                file_path: rec.file_path.clone(),
                line_number: rec.line_number,
                rule_id: rec.rule_id.clone(),
                cve_id: rec.cve_id.clone(),
                severity: rec.severity.clone(),
                message: rec.message.clone(),
                transmitted_data: rec.transmitted_data.clone(),
                transmitted_type: rec.transmitted_type.clone(),
                remediation: rec.remediation.clone(),
            });
        }
    }
    (violations, file_count)
}

async fn run_sca_only_cli(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let raw = args.path.trim().trim_matches('"').trim_matches('\'');
    let clean = raw.strip_prefix(r"\\?\").unwrap_or(raw);
    let project_root = if clean.is_empty() || clean == "." {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        fs::canonicalize(clean).unwrap_or_else(|_| PathBuf::from(&clean))
    };

    println!("ðŸ“¦ [SCA] Scanning dependencies in `{}` (offline: {})...", project_root.display(), args.offline_sca);
    let mut sca_report = security_linter::sca::ScaEngine::scan_project(&project_root, args.offline_sca)?;
    println!("   Discovered {} dependencies across lockfiles.", sca_report.dependencies.len());

    let scanner = ProjectScanner::default();
    let mut graph = scanner.scan_project(&project_root);
    security_linter::sca::ScaEngine::cross_reference_reachability(&mut graph, &mut sca_report);

    println!("\nâ”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”");
    println!("ðŸ“Š AETHERSCOPE SOFTWARE COMPOSITION ANALYSIS (SCA) REPORT");
    println!("â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”");
    println!("   â€¢ Total Dependencies      : {}", sca_report.dependencies.len());
    println!("   â€¢ Total Vulnerabilities   : {}", sca_report.total_vulnerabilities);
    println!("   â€¢ ðŸ”´ REACHABLE (High Risk): {}", sca_report.reachable_count);
    println!("   â€¢ âšª Unreachable (Low Risk): {}", sca_report.unreachable_count);
    println!("â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\n");

    if sca_report.reachable_count > 0 {
        println!("ðŸš¨ REACHABLE VULNERABILITIES (Called from Entrypoints / Endpoints) :");
        for v in sca_report.vulnerabilities.iter().filter(|v| v.is_reachable) {
            println!("  ðŸ”´ [{}] {} v{} â€” {}", v.cve_id, v.dependency.name, v.dependency.version, v.severity);
            println!("     Summary     : {}", v.summary);
            println!("     Exploit Path: {}", v.exploit_path.join(" -> "));
            println!("     Remediation : {}\n", v.remediation);
        }
    }

    if sca_report.unreachable_count > 0 {
        println!("ðŸ›¡ï¸ UNREACHABLE VULNERABILITIES (Dead Code / Unexposed Dependencies) :");
        for v in sca_report.vulnerabilities.iter().filter(|v| !v.is_reachable) {
            println!("  âšª [{}] {} v{} â€” {}", v.cve_id, v.dependency.name, v.dependency.version, v.severity);
            println!("     Summary     : {}", v.summary);
            println!("     Remediation : {}\n", v.remediation);
        }
    }

    // CI/CD Failure gate: evaluate --fail-on
    if let Some(ref fail_threshold) = args.fail_on {
        let threshold = fail_threshold.trim().to_uppercase();
        let mut failed = false;
        for v in sca_report.vulnerabilities.iter().filter(|v| v.is_reachable) {
            let sev = v.severity.trim().to_uppercase();
            let triggered = match threshold.as_str() {
                "CRITICAL" => sev == "CRITICAL",
                "HIGH" => sev == "CRITICAL" || sev == "HIGH",
                "MEDIUM" => sev == "CRITICAL" || sev == "HIGH" || sev == "MEDIUM",
                _ => false,
            };
            if triggered {
                eprintln!(
                    "âŒ [GATE] Reachable SCA vulnerability {} ({}) exceeds failure threshold `{}`",
                    v.cve_id, sev, threshold
                );
                failed = true;
            }
        }
        if failed {
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn run_audit_cli(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let start_instant = std::time::Instant::now();
    let raw = args.path.trim().trim_matches('"').trim_matches('\'');
    let clean = raw.strip_prefix(r"\\?\").unwrap_or(raw);
    let project_root = if clean.is_empty() || clean == "." {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        fs::canonicalize(clean).unwrap_or_else(|_| PathBuf::from(&clean))
    };

    AuditWriter::ensure_master_rules_file(&project_root)?;
    let (scanner, plugin_engine) = match resolve_scanner_for_args(&project_root, args.plugins.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ [PLUGINS] {}", e);
            std::process::exit(1);
        }
    };
    let mut graph = scanner.scan_project(&project_root);

    if args.sca || args.offline_sca {
        println!("ðŸ“¦ [SCA] Analyzing software dependencies (offline: {})...", args.offline_sca);
        match security_linter::sca::ScaEngine::scan_project(&project_root, args.offline_sca) {
            Ok(mut sca_report) => {
                security_linter::sca::ScaEngine::cross_reference_reachability(&mut graph, &mut sca_report);
                println!(
                    "   SCA: {} dependencies, {} vulnerabilities ({} reachable, {} unreachable)",
                    sca_report.dependencies.len(),
                    sca_report.total_vulnerabilities,
                    sca_report.reachable_count,
                    sca_report.unreachable_count
                );
            }
            Err(e) => {
                eprintln!("âš ï¸ [SCA] Error scanning dependencies: {}", e);
            }
        }
    }


    let (all_violations, file_count) = extract_live_audit_from_graph(&graph);
    let mut all_anomalies: Vec<core_graph::bubble::CveAnomalyRecord> = Vec::new();
    for node in &graph.nodes {
        all_anomalies.extend(node.metadata.cve_anomalies.clone());
    }

    let is_sarif = args.format.eq_ignore_ascii_case("sarif");

    if is_sarif {
        let mut active_rules = if !matches!(
            scanner.plugin_selection,
            security_linter::PluginSelection::Select(_)
        ) {
            security_linter::SecurityLinter::get_supported_cve_rules()
        } else {
            Vec::new()
        };
        active_rules.extend(plugin_engine.get_cve_rule_defs());
        let sarif_report = security_linter::sarif::SarifReport::from_anomalies_with_root(
            &all_anomalies,
            Some(&active_rules),
            Some(&project_root),
        );
        let sarif_json = sarif_report.to_json_string_pretty()?;

        if let Some(ref out_path) = args.output {
            let out_file = Path::new(out_path);
            if let Some(parent) = out_file.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = fs::create_dir_all(parent);
                }
            }
            fs::write(out_file, &sarif_json)?;
            println!(
                "âœ… [SARIF] Rapport SARIF v2.1.0 Ã©crit dans `{}` ({} rÃ©sultats)",
                out_file.display(),
                all_anomalies.len()
            );
        } else {
            println!("{}", sarif_json);
        }
    } else {
        AuditWriter::write_live_audit(&project_root, &all_violations, file_count)?;
        println!(
            "âœ… [SAST] Audit terminÃ© sur `{}` : {} nÅ“uds, {} flux, {} violations dans .aether/LIVE_AUDIT.md ({} fichiers auditÃ©s)",
            project_root.display(),
            graph.nodes.len(),
            graph.edges.len(),
            all_violations.len(),
            file_count
        );
        if let Some(ref out_path) = args.output {
            let live_audit_path = project_root.join(".aether").join("LIVE_AUDIT.md");
            if live_audit_path.exists() {
                let out_file = Path::new(out_path);
                if let Some(parent) = out_file.parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = fs::create_dir_all(parent);
                    }
                }
                let _ = fs::copy(&live_audit_path, out_file);
            }
        }
    }

    // CI/CD Failure gate: evaluate --fail-on
    if let Some(ref fail_threshold) = args.fail_on {
        let threshold = fail_threshold.trim().to_uppercase();
        let mut failed_violations = Vec::new();

        for a in &all_anomalies {
            if a.taint_trace.as_ref().is_some_and(|t| t.is_sanitized) {
                continue;
            }
            let sev = a.severity.trim().to_uppercase();
            let triggered = match threshold.as_str() {
                "CRITICAL" => sev == "CRITICAL",
                "HIGH" => sev == "CRITICAL" || sev == "HIGH",
                "MEDIUM" => sev == "CRITICAL" || sev == "HIGH" || sev == "MEDIUM",
                "LOW" | "WARNING" => {
                    sev == "CRITICAL"
                        || sev == "HIGH"
                        || sev == "MEDIUM"
                        || sev == "LOW"
                        || sev == "WARNING"
                }
                _ => sev == threshold,
            };
            if triggered {
                failed_violations.push(a);
            }
        }

        if !failed_violations.is_empty() {
            let elapsed = start_instant.elapsed();
            eprintln!(
                "âŒ [FAIL-ON: {}] {} infraction(s) bloquante(s) dÃ©tectÃ©e(s) en {:?} (seuil: {}). Blocage de la PR.",
                threshold,
                failed_violations.len(),
                elapsed,
                threshold
            );
            for fv in failed_violations.iter().take(5) {
                eprintln!(
                    "   â€¢ [{}] L{}: {} ({})",
                    fv.rule_id, fv.line_number, fv.file_path, fv.message
                );
            }
            if failed_violations.len() > 5 {
                eprintln!(
                    "   ... et {} autre(s) violation(s).",
                    failed_violations.len() - 5
                );
            }
            std::process::exit(1);
        }
    }

    if is_sarif && args.output.is_none() {
        return Ok(());
    }

    if mcp::check_server_listening(args.port) {
        println!(
            "ðŸ“¡ [SYNCHRO EN DIRECT] Cockpit AetherScope dÃ©tectÃ© sur http://127.0.0.1:{} : actualisation du Cockpit 3D & du MCP...",
            args.port
        );
        let path_str = clean_path_string(&project_root);
        match mcp::send_http_request(
            args.port,
            "POST",
            "/api/analyze",
            Some(&serde_json::json!({ "path": path_str })),
        )
        .await
        {
            Ok(_) => {
                println!("ðŸš€ [OK] Graphe WebGL 3D et passerelle MCP synchronisÃ©s en temps rÃ©el !");
            }
            Err(e) => {
                eprintln!("âš ï¸ Ã‰chec synchronisation en direct avec le Cockpit ({})", e);
            }
        }
    } else {
        println!(
            "â„¹ï¸ Serveur Cockpit non actif sur le port {}. Lancez le Cockpit via le Launcher pour visualiser le graphe en 3D.",
            args.port
        );
    }

    Ok(())
}

fn is_lines_budget_anomaly(rule_id: &str, cve_id: &str, severity: &str) -> bool {
    rule_id == "RULE_MAX_LINES"
        || cve_id.contains("ARCH-BUDGET-EXCEEDED")
        || cve_id.contains("CONTRACT / ARCH-BUDGET")
        || cve_id == "CONTRACT_BUDGET"
        || (severity == "WARNING" && (rule_id.contains("LINE") || cve_id.contains("BUDGET")))
}

fn native_builtin_rule_ids() -> &'static std::collections::HashSet<String> {
    static NATIVE_IDS: std::sync::OnceLock<std::collections::HashSet<String>> =
        std::sync::OnceLock::new();
    NATIVE_IDS.get_or_init(|| {
        security_linter::SecurityLinter::get_supported_cve_rules()
            .into_iter()
            .map(|r| r.rule_id)
            .collect()
    })
}

pub(crate) fn apply_settings_filters_to_graph(
    graph: &mut core_graph::graph::AetherGraph,
    active_opt: Option<&[String]>,
    ignored_cwes: &[String],
) {
    let ignored_set: std::collections::HashSet<String> = ignored_cwes
        .iter()
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();
    if active_opt.is_none() && ignored_set.is_empty() {
        return;
    }
    let allowed_set_opt: Option<std::collections::HashSet<&str>> = active_opt
        .map(|allowed| allowed.iter().map(|s| s.as_str()).collect());
    let native_ids = native_builtin_rule_ids();

    let is_violation_allowed = |rule_str: &str, cve_str: &str| -> bool {
        if let Some(ref allowed_set) = allowed_set_opt {
            let exempt_blake3 = rule_str == "BLAKE3_TAMPERED" && !allowed_set.is_empty();
            // Custom plugin, Semgrep, and declarative taint-sink rules are governed by their
            // manifest `enabled` flag + `ignored_cwes`, not silently dropped by a saved native-only
            // `active_cve_rules` list (while still honoring an explicit empty "disable all" list).
            let is_custom_plugin_rule =
                !rule_str.is_empty() && !native_ids.contains(rule_str) && !allowed_set.is_empty();
            if !rule_str.is_empty()
                && rule_str != "RULE_MAX_LINES"
                && !matches!(
                    rule_str,
                    "RULE_MAX_FILES" | "RULE_FORBIDDEN_FUNCTION" | "RULE_FORBIDDEN_EXTENSION"
                )
                && !allowed_set.contains(rule_str)
                && !exempt_blake3
                && !is_custom_plugin_rule
            {
                return false;
            }
        }
        let rule_up = rule_str.to_uppercase();
        let cve_up = cve_str.to_uppercase();
        if !rule_up.is_empty() && ignored_set.contains(&rule_up) {
            return false;
        }
        if !cve_up.is_empty() && ignored_set.contains(&cve_up) {
            return false;
        }
        if ignored_set.iter().any(|ign| {
            (!cve_up.is_empty() && cve_up.contains(ign))
                || (!rule_up.is_empty() && rule_up.contains(ign))
        }) {
            return false;
        }
        true
    };

    let mut files_with_active_sym_cwe: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for node in &mut graph.nodes {
        node.metadata
            .cve_anomalies
            .retain(|a| is_violation_allowed(a.rule_id.as_str(), a.cve_id.as_str()));

        node.metadata.violations.retain(|raw| {
            let trimmed = raw.trim();
            let (rule_str, rest) = if let Some(after_open) = trimmed.strip_prefix('[') {
                if let Some(close_idx) = after_open.find(']') {
                    (&after_open[..close_idx], after_open[close_idx + 1..].trim())
                } else {
                    ("", trimmed)
                }
            } else {
                ("", trimmed)
            };
            let cve_str = if let Some(after_p) = rest.strip_prefix('(') {
                if let Some(end_p) = after_p.find(')') {
                    let inside = &after_p[..end_p];
                    inside.split('|').next().unwrap_or("").trim()
                } else {
                    ""
                }
            } else {
                ""
            };
            is_violation_allowed(rule_str, cve_str)
        });

        let has_non_lines_cwe = node
            .metadata
            .cve_anomalies
            .iter()
            .any(|a| !is_lines_budget_anomaly(&a.rule_id, &a.cve_id, &a.severity));
        if !node.is_file {
            node.has_security_violation = has_non_lines_cwe;
            if has_non_lines_cwe {
                files_with_active_sym_cwe.insert(node.file_path.clone());
            }
        }
    }

    for node in &mut graph.nodes {
        if node.is_file {
            let has_own_non_lines = node
                .metadata
                .cve_anomalies
                .iter()
                .any(|a| !is_lines_budget_anomaly(&a.rule_id, &a.cve_id, &a.severity));
            node.has_security_violation =
                has_own_non_lines || files_with_active_sym_cwe.contains(&node.file_path);
        }
    }
}

/// Core pipeline executing deterministic project detection, dual vault/code scanning,
/// state caching, SAST live audit, and cockpit HUD telemetry emission.
pub async fn execute_project_pipeline(
    state: &AppState,
    path: PathBuf,
    exclusions: Option<Vec<String>>,
) -> core_graph::graph::AetherGraph {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let proj_display = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Projet".to_string());

    let mut custom_excl = state.custom_exclusions.read().await.clone();
    if let Some(req_excl) = exclusions {
        custom_excl = req_excl.clone();
        let mut excl_guard = state.custom_exclusions.write().await;
        *excl_guard = req_excl;
    }

    // 1. Détection automatique du type de projet
    let scan_path = path.clone();
    let detection_report = tokio::task::spawn_blocking(move || {
        obsidian_vault::detect_project_type(&scan_path)
    })
    .await
    .unwrap_or_else(|_| {
        Ok(obsidian_vault::ProjectDetectionReport::new(
            obsidian_vault::DetectedProjectType::PureCode,
            false,
            None,
            0,
            0,
            0,
        ))
    })
    .unwrap_or_else(|_| {
        obsidian_vault::ProjectDetectionReport::new(
            obsidian_vault::DetectedProjectType::PureCode,
            false,
            None,
            0,
            0,
            0,
        )
    });

    let p_type = detection_report.project_type;

    // 2. Scan selon la classification
    let (active_graph, final_mode) = match p_type {
        obsidian_vault::DetectedProjectType::PureObsidianVault => {
            let scan_path = path.clone();
            let vault_g = tokio::task::spawn_blocking(move || {
                obsidian_vault::scan_obsidian_vault(&scan_path)
            })
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or_else(|| core_graph::graph::AetherGraph::new(&proj_display));

            *state.code_graph.write().await = None;
            *state.vault_graph.write().await = Some(vault_g.clone());
            (vault_g, "vault".to_string())
        }
        obsidian_vault::DetectedProjectType::PureCode => {
            let scan_path = path.clone();
            let excl = custom_excl.clone();
            let sel = state.plugin_selection.clone();
            let active_rules = state.active_cve_rules.read().await.clone();
            let ignored_cwes = state.ignored_cwes.read().await.clone();
            let mut code_g = tokio::task::spawn_blocking(move || {
                let scanner = ProjectScanner::default().with_plugin_selection(sel);
                scanner.scan_project_with_exclusions(&scan_path, &excl)
            })
            .await
            .unwrap_or_else(|_| core_graph::graph::AetherGraph::new(&proj_display));
            apply_settings_filters_to_graph(&mut code_g, active_rules.as_deref(), &ignored_cwes);

            *state.code_graph.write().await = Some(code_g.clone());
            *state.vault_graph.write().await = None;
            (code_g, "code".to_string())
        }
        obsidian_vault::DetectedProjectType::Mixed => {
            let scan_path1 = path.clone();
            let scan_path2 = path.clone();
            let excl = custom_excl.clone();
            let sel = state.plugin_selection.clone();
            let active_rules = state.active_cve_rules.read().await.clone();
            let ignored_cwes = state.ignored_cwes.read().await.clone();

            let (code_res, vault_res) = tokio::join!(
                tokio::task::spawn_blocking(move || {
                    let scanner = ProjectScanner::default().with_plugin_selection(sel);
                    scanner.scan_project_with_exclusions(&scan_path1, &excl)
                }),
                tokio::task::spawn_blocking(move || {
                    obsidian_vault::scan_obsidian_vault(&scan_path2)
                })
            );

            let mut code_g = code_res.unwrap_or_else(|_| core_graph::graph::AetherGraph::new(&proj_display));
            apply_settings_filters_to_graph(&mut code_g, active_rules.as_deref(), &ignored_cwes);
            let vault_g = match vault_res {
                Ok(Ok(g)) => g,
                Ok(Err(e)) => {
                    eprintln!("⚠️ [OBSIDIAN] Échec scan vault dans dossier mixte: {:?}", e);
                    core_graph::graph::AetherGraph::new(&proj_display)
                }
                Err(err) => {
                    eprintln!("⚠️ [OBSIDIAN] JoinError scan vault: {:?}", err);
                    core_graph::graph::AetherGraph::new(&proj_display)
                }
            };

            *state.code_graph.write().await = Some(code_g.clone());
            *state.vault_graph.write().await = Some(vault_g.clone());

            let current_view = state.active_view_mode.read().await.clone();
            if current_view == "vault" {
                (vault_g, "vault".to_string())
            } else {
                (code_g, "code".to_string())
            }
        }
    };

    // 3. Mise à jour de l'état partagé
    let prev_root = state.project_root.read().await.clone();
    *state.project_type.write().await = p_type;
    *state.detection_report.write().await = Some(detection_report);
    *state.active_view_mode.write().await = final_mode.clone();
    *state.graph.write().await = active_graph.clone();
    *state.project_root.write().await = path.clone();
    if prev_root != path {
        state.reload_telemetry_cache(&path).await;
    }
    state.graph_version.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    // 4. Audit SAST si code présent
    if let Some(ref code_g) = *state.code_graph.read().await {
        let _ = AuditWriter::ensure_master_rules_file(&path);
        let (violations, file_count) = extract_live_audit_from_graph(code_g);
        let _ = AuditWriter::write_live_audit(&path, &violations, file_count);

        if p_type == obsidian_vault::DetectedProjectType::PureCode {
            let mut t_guard = state.telemetry.write().await;
            let failles_count = violations
                .iter()
                .filter(|v| v.rule_id != "RULE_MAX_LINES" && v.severity != "WARNING" && !v.cve_id.contains("ARCH-BUDGET-EXCEEDED"))
                .count();
            *t_guard = Some(AiTelemetryEvent {
                target: proj_display.clone(),
                action: "Analyse AST & SAST Live".to_string(),
                details: format!(
                    "Codebase actualisée : {} nœuds, {} flux, {} failles SAST",
                    code_g.nodes.len(),
                    code_g.edges.len(),
                    failles_count
                ),
                timestamp: now_ms,
                ..Default::default()
            });

            let mut chat_guard = state.chat_messages.write().await;
            chat_guard.push(AiChatMessage {
                id: format!("msg_{}", now_ms),
                sender: "system".to_string(),
                text: format!(
                    "⚡ Analyse terminée pour `{}` : {} symboles, {} liaisons, {} règles de sécurité auditées.",
                    proj_display,
                    code_g.nodes.len(),
                    code_g.edges.len(),
                    violations.len()
                ),
                target_symbol: Some(proj_display.clone()),
                timestamp: now_ms,
                ..Default::default()
            });
        }
    }

    // 5. Télémétrie HUD et Chat spécifiques Obsidian & Hybride
    match p_type {
        obsidian_vault::DetectedProjectType::PureObsidianVault => {
            let mut t_guard = state.telemetry.write().await;
            *t_guard = Some(AiTelemetryEvent {
                target: proj_display.clone(),
                action: "Scan Obsidian Vault".to_string(),
                details: format!(
                    "Obsidian Knowledge Base : {} notes & médias, {} liaisons",
                    active_graph.nodes.len(),
                    active_graph.edges.len()
                ),
                timestamp: now_ms,
                ..Default::default()
            });

            let mut chat_guard = state.chat_messages.write().await;
            chat_guard.push(AiChatMessage {
                id: format!("msg_{}", now_ms),
                sender: "system".to_string(),
                text: format!(
                    "⚡ Obsidian Vault chargé pour `{}` : {} notes, {} wikilinks & transclusions.",
                    proj_display,
                    active_graph.nodes.len(),
                    active_graph.edges.len()
                ),
                target_symbol: Some(proj_display.clone()),
                timestamp: now_ms,
                ..Default::default()
            });
        }
        obsidian_vault::DetectedProjectType::Mixed => {
            let code_count = state.code_graph.read().await.as_ref().map(|g| g.nodes.len()).unwrap_or(0);
            let vault_count = state.vault_graph.read().await.as_ref().map(|g| g.nodes.len()).unwrap_or(0);

            let mut t_guard = state.telemetry.write().await;
            *t_guard = Some(AiTelemetryEvent {
                target: proj_display.clone(),
                action: "Analyse Mixte (Code + Obsidian)".to_string(),
                details: format!(
                    "Dossier Mixte : {} symboles code, {} notes vault (vue active: {})",
                    code_count,
                    vault_count,
                    final_mode
                ),
                timestamp: now_ms,
                ..Default::default()
            });

            let mut chat_guard = state.chat_messages.write().await;
            chat_guard.push(AiChatMessage {
                id: format!("msg_{}", now_ms),
                sender: "system".to_string(),
                text: format!(
                    "⚡ Projet Mixte analysé pour `{}` : {} symboles code, {} notes Obsidian. Bascule dynamique disponible !",
                    proj_display,
                    code_count,
                    vault_count
                ),
                target_symbol: Some(proj_display.clone()),
                timestamp: now_ms,
                ..Default::default()
            });
        }
        obsidian_vault::DetectedProjectType::PureCode => {}
    }

    active_graph
}

pub async fn run_server_and_watcher(args: Args) -> Result<(), Box<dyn std::error::Error>> {

    let project_root = fs::canonicalize(Path::new(&args.path)).unwrap_or_else(|_| PathBuf::from(&args.path));
    let (scanner, _) = match resolve_scanner_for_args(&project_root, args.plugins.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ [PLUGINS] {}", e);
            std::process::exit(1);
        }
    };
    let plugin_selection = scanner.plugin_selection.clone();

    AuditWriter::ensure_master_rules_file(&project_root)?;

    // 1. Detect project type
    let detection_report = obsidian_vault::detect_project_type(&project_root).ok();
    let project_type = detection_report
        .as_ref()
        .map(|r| r.project_type)
        .unwrap_or(obsidian_vault::DetectedProjectType::PureCode);
    let active_view_mode = detection_report
        .as_ref()
        .map(|r| r.default_view.clone())
        .unwrap_or_else(|| "code".to_string());

    // 2. Scan code graph if project has code (respecting saved exclusions & CWE filters from .aether/settings.json)
    let saved_settings = load_project_settings(&project_root);
    let code_graph = if project_type.is_code() || project_type.is_mixed() {
        let mut g = match saved_settings.as_ref() {
            Some(s) if !s.exclusions.is_empty() => scanner.scan_project_with_exclusions(&project_root, &s.exclusions),
            _ => scanner.scan_project(&project_root),
        };
        if let Some(ref s) = saved_settings {
            apply_settings_filters_to_graph(
                &mut g,
                s.active_cve_rules.as_deref(),
                s.ignored_cwes.as_deref().unwrap_or(&[]),
            );
        }
        let (all_violations, audited_files_count) = extract_live_audit_from_graph(&g);
        let _ = AuditWriter::write_live_audit(&project_root, &all_violations, audited_files_count);
        Some(g)
    } else {
        None
    };

    // 3. Scan vault graph if project has vault notes
    let vault_graph = if project_type.is_vault() || project_type.is_mixed() {
        match obsidian_vault::scan_obsidian_vault(&project_root) {
            Ok(g) => Some(g),
            Err(e) => {
                eprintln!("⚠️ Warning: Obsidian vault scan failed: {e}");
                None
            }
        }
    } else {
        None
    };

    // 4. Initial active graph matching default view mode
    let initial_active_graph = match active_view_mode.as_str() {
        "vault" => vault_graph.clone().or_else(|| code_graph.clone()),
        _ => code_graph.clone().or_else(|| vault_graph.clone()),
    }
    .unwrap_or_else(|| core_graph::graph::AetherGraph::new("Project"));

    let shared_state = Arc::new(
        AppState::new(
            initial_active_graph,
            project_root.clone(),
            project_type,
            active_view_mode,
            code_graph,
            vault_graph,
            detection_report,
        )
        .with_plugin_selection(plugin_selection),
    );

    // FileWatcher background loop with adaptive debouncer (100ms quiet window, 500ms max burst wait)
    let watcher_root = project_root.clone();
    let watcher_state = shared_state.clone();

    tokio::spawn(async move {
        if let Ok(mut watcher) = FileWatcherBridge::new(&watcher_root) {
            let mut pending_changes = std::collections::HashSet::new();
            let mut first_change_time: Option<std::time::Instant> = None;
            let mut last_change_time: Option<std::time::Instant> = None;
            let debounce_delay = std::time::Duration::from_millis(100);
            let max_batch_delay = std::time::Duration::from_millis(500);

            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
                let current_root = watcher_state.project_root.read().await.clone();
                if current_root != watcher.project_root {
                    let _ = watcher.switch_root(&current_root);
                    pending_changes.clear();
                    first_change_time = None;
                    last_change_time = None;
                }

                let changed = watcher.poll_changed_files();
                if !changed.is_empty() {
                    let now = std::time::Instant::now();
                    if first_change_time.is_none() {
                        first_change_time = Some(now);
                    }
                    for file in changed {
                        pending_changes.insert(file);
                    }
                    last_change_time = Some(now);
                }

                // Trigger re-scan when quiet window (100ms) has elapsed OR max burst window (500ms) reached
                let should_trigger = !pending_changes.is_empty()
                    && (last_change_time.is_some_and(|t| t.elapsed() >= debounce_delay)
                        || first_change_time.is_some_and(|t| t.elapsed() >= max_batch_delay));

                if should_trigger {
                    let files_to_process = std::mem::take(&mut pending_changes);
                    first_change_time = None;
                    last_change_time = None;

                    // Invalidate cached git status so subsequent git diff queries see disk changes immediately
                    *watcher_state.git_raw_cache.lock().await = None;

                    let rel_changed_files: Vec<String> = files_to_process
                        .iter()
                        .map(|p| {
                            p.strip_prefix(&current_root)
                                .unwrap_or(p)
                                .to_string_lossy()
                                .replace('\\', "/")
                        })
                        .filter(|s| !s.is_empty())
                        .collect();

                    let current_mode = watcher_state.get_active_view_mode().await;
                    let is_vault_mode = current_mode == "vault" || current_mode == "vault-notes";
                    let is_visual_plugin_file = |p: &std::path::Path| -> bool {
                        let s = p.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
                        s.contains(".aether/plugins/visuals/")
                            || p.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("glsl"))
                    };
                    let has_visual_changes = files_to_process.iter().any(|p| is_visual_plugin_file(p));
                    if has_visual_changes {
                        watcher_state
                            .visual_plugins_version
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }

                    let has_dir_changes = files_to_process
                        .iter()
                        .any(|p| p.extension().is_none() || p.is_dir());
                    let has_readme_changes = files_to_process.iter().any(|p| {
                        p.file_name()
                            .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("readme.md"))
                    });
                    let has_md_changes = has_dir_changes
                        || files_to_process.iter().any(|p| {
                            p.extension().is_some_and(|ext| {
                                ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("mdx")
                            })
                        });
                    let has_code_changes = has_dir_changes
                        || has_readme_changes
                        || files_to_process.iter().any(|p| {
                            !is_visual_plugin_file(p)
                                && p.extension().is_some_and(|ext| {
                                    !ext.eq_ignore_ascii_case("md") && !ext.eq_ignore_ascii_case("mdx")
                                })
                        });

                    *watcher_state.last_changed_files.write().await = rel_changed_files.clone();

                    if has_visual_changes && !has_md_changes && !has_code_changes {
                        watcher_state.notify_graph_change(rel_changed_files, "visual");
                        continue;
                    }

                    let p_type = *watcher_state.project_type.read().await;

                    // Refresh vault graph if md changed in a vault/mixed project or in vault mode
                    if (has_md_changes && (p_type.is_vault() || p_type.is_mixed())) || is_vault_mode {
                        let scan_root = current_root.clone();
                        if let Ok(Ok(v_graph)) = tokio::task::spawn_blocking(move || {
                            obsidian_vault::scan_obsidian_vault(&scan_root)
                        })
                        .await
                        {
                            *watcher_state.vault_graph.write().await = Some(v_graph.clone());
                            if is_vault_mode {
                                *watcher_state.graph.write().await = v_graph;
                                *watcher_state.ui_graph_cache.write().await = None;
                                watcher_state
                                    .graph_version
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    }

                    // Refresh code graph if code/README/folder changed
                    if has_code_changes {
                        let custom_excl = watcher_state.custom_exclusions.read().await.clone();
                        let active_rules = watcher_state.active_cve_rules.read().await.clone();
                        let ignored_cwes = watcher_state.ignored_cwes.read().await.clone();
                        let scan_root = current_root.clone();
                        let sel = watcher_state.plugin_selection.clone();
                        if let Ok(mut updated_graph) = tokio::task::spawn_blocking(move || {
                            let scanner = ProjectScanner::default().with_plugin_selection(sel);
                            scanner.scan_project_with_exclusions(&scan_root, &custom_excl)
                        })
                        .await
                        {
                            apply_settings_filters_to_graph(
                                &mut updated_graph,
                                active_rules.as_deref(),
                                &ignored_cwes,
                            );
                            let (violations, file_count) = extract_live_audit_from_graph(&updated_graph);
                            let _ = AuditWriter::write_live_audit(&current_root, &violations, file_count);
                            *watcher_state.code_graph.write().await = Some(updated_graph.clone());
                            if !is_vault_mode {
                                *watcher_state.graph.write().await = updated_graph;
                                *watcher_state.ui_graph_cache.write().await = None;
                                watcher_state
                                    .graph_version
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    }

                    watcher_state.notify_graph_change(rel_changed_files, "watcher");
                }
            }
        }
    });

    let state_viewer = shared_state.clone();
    let state_graph = shared_state.clone();
    let state_graph_version = shared_state.clone();
    let state_graph_events = shared_state.clone();
    let state_projects = shared_state.clone();
    let state_analyze = shared_state.clone();
    let state_analyze_get = shared_state.clone();
    let state_export = shared_state.clone();
    let state_savedoc = shared_state.clone();
    let state_sign_contracts = shared_state.clone();
    let state_update_contract = shared_state.clone();
    let state_pick_ws = shared_state.clone();
    let state_pick_proj = shared_state.clone();
    let state_fs_list = shared_state.clone();
    let state_init_proj = shared_state.clone();
    let state_workspace = shared_state.clone();
    let state_telemetry = shared_state.clone();
    let state_ai_target = shared_state.clone();
    let state_chat = shared_state.clone();
    let state_create_file = shared_state.clone();
    let state_sysprompt = shared_state.clone();
    let state_file_content = shared_state.clone();
    let state_raw_file = shared_state.clone();
    let state_ai_cancel = shared_state.clone();
    let state_ai_session = shared_state.clone();
    let state_ai_cli = shared_state.clone();
    let state_settings = shared_state.clone();
    let state_git_status = shared_state.clone();
    let state_tasks = shared_state.clone();
    let state_project_status = shared_state.clone();
    let state_view_mode = shared_state.clone();
    let state_save_file = shared_state.clone();
    let state_files = shared_state.clone();
    let server_port = args.port;

    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::get({
                let state_modern = state_viewer.clone();
                move || {
                    let state = state_modern.clone();
                    async move {
                        let p_type = *state.project_type.read().await;
                        let active_view = state.active_view_mode.read().await.clone();
                        let code_g = state.code_graph.read().await;
                        let vault_g = state.vault_graph.read().await;
                        let g = state.graph.read().await;
                        let html = viewer::generate_modern_standalone_html(
                            code_g.as_ref().or(Some(&*g)),
                            vault_g.as_ref(),
                            p_type,
                            &active_view,
                        );
                        (
                            [(axum::http::header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")],
                            axum::response::Html(html),
                        )
                    }
                }
            }),
        )
        .route(
            "/legacy",
            axum::routing::get(move || {
                let state = state_viewer.clone();
                async move {
                    let p_type = *state.project_type.read().await;
                    let active_view = state.active_view_mode.read().await.clone();
                    let code_g = state.code_graph.read().await;
                    let vault_g = state.vault_graph.read().await;
                    let g = state.graph.read().await;
                    let html = viewer::generate_modern_standalone_html(
                        code_g.as_ref().or(Some(&*g)),
                        vault_g.as_ref(),
                        p_type,
                        &active_view,
                    );
                    (
                        [(axum::http::header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")],
                        axum::response::Html(html),
                    )
                }
            }),
        )
        .route(
            "/api/projects",
            axum::routing::get(move || {
                let state = state_projects.clone();
                async move {
                    let p_root = state.project_root.read().await;
                    let projects = discover_candidate_projects(&p_root);
                    let default_project = Some(clean_path_string(&p_root));
                    axum::Json(ProjectsResponse {
                        projects,
                        default_project,
                    })
                }
            }),
        )
        .route(
            "/api/workspace",
            axum::routing::get({
                let state = state_workspace.clone();
                move || async move {
                    let p = state.project_root.read().await;
                    axum::Json(serde_json::json!({ "workspace": p.to_string_lossy() }))
                }
            })
            .post({
                let state = state_workspace.clone();
                move |axum::extract::Json(payload): axum::extract::Json<serde_json::Value>| async move {
                    if let Some(ws) = payload.get("workspace").and_then(|v| v.as_str()) {
                        let mut p = state.project_root.write().await;
                        *p = PathBuf::from(ws);
                    }
                    axum::Json(serde_json::json!({ "status": "ok" }))
                }
            }),
        )
        // Explorateur de dossiers & workspaces côté serveur (navigation fluide sans blocage de dialogue natif)
        .route(
            "/api/fs/list",
            axum::routing::get({
                let state = state_fs_list.clone();
                move |axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>| {
                    let state = state.clone();
                    async move {
                        let req_path = query.get("path").cloned();
                        let fallback_root = state.project_root.read().await.clone();
                        let resp = tokio::task::spawn_blocking(move || {
                            list_directory_entries(req_path.as_deref(), &fallback_root)
                        })
                        .await
                        .unwrap_or_else(|e| FsListResponse {
                            status: "error".to_string(),
                            current_path: String::new(),
                            parent_path: None,
                            drives: Vec::new(),
                            entries: Vec::new(),
                            message: Some(format!("Erreur lecture dossier : {}", e)),
                        });
                        axum::Json(resp)
                    }
                }
            }),
        )
        // Dialogue natif : Choisir le dossier contenant TOUS les projets (ne modifie pas project_root avant analyse)
        .route(
            "/api/dialog/pick_workspace",
            axum::routing::post(move || {
                let state = state_pick_ws.clone();
                async move {
                    let init_dir = {
                        let p = state.project_root.read().await;
                        p.parent().map(Path::to_path_buf).unwrap_or_else(|| p.clone())
                    };
                    let chosen = tokio::task::spawn_blocking(move || {
                        pick_folder_dialog_in(
                            "Sélectionnez le dossier racine contenant tous les projets",
                            Some(&init_dir),
                        )
                    })
                    .await
                    .ok()
                    .flatten();

                    if let Some(folder) = chosen {
                        let path_str = clean_path_string(&folder);
                        let projects = discover_candidate_projects(&folder);
                        axum::Json(PickWorkspaceResponse {
                            status: "ok".to_string(),
                            workspace: Some(path_str),
                            projects,
                        })
                    } else {
                        axum::Json(PickWorkspaceResponse {
                            status: "cancelled".to_string(),
                            workspace: None,
                            projects: Vec::new(),
                        })
                    }
                }
            }),
        )
        // Dialogue natif : Choisir 1 projet unique
        .route(
            "/api/dialog/pick_project",
            axum::routing::post(move || {
                let state = state_pick_proj.clone();
                async move {
                    let init_dir = {
                        let p = state.project_root.read().await;
                        p.parent().map(Path::to_path_buf).unwrap_or_else(|| p.clone())
                    };
                    let chosen = tokio::task::spawn_blocking(move || {
                        pick_folder_dialog_in(
                            "Sélectionnez le projet à ouvrir et analyser",
                            Some(&init_dir),
                        )
                    })
                    .await
                    .ok()
                    .flatten();

                    if let Some(folder) = chosen {
                        let path_str = clean_path_string(&folder);
                        let active_graph = execute_project_pipeline(&state, folder, None).await;
                        axum::Json(PickProjectResponse {
                            status: "ok".to_string(),
                            project_path: Some(path_str),
                            graph: Some(active_graph),
                        })
                    } else {
                        axum::Json(PickProjectResponse {
                            status: "cancelled".to_string(),
                            project_path: None,
                            graph: None,
                        })
                    }
                }
            }),
        )
        // Scaffolding d'architecture projet
        .route(
            "/api/init_project",
            axum::routing::post(move |axum::extract::Json(req): axum::extract::Json<InitProjectRequest>| {
                let _state = state_init_proj.clone();
                async move {
                    let base = Path::new(&req.path);
                    let created = api_routes::init_project_structure_with_topology(
                        base,
                        &req.stack,
                        req.topology.as_deref(),
                    );
                    axum::Json(InitProjectResponse {
                        status: "ok".to_string(),
                        message: format!("Projet initialisÃ© avec {} dossiers et contrats README.md signÃ©s BLAKE3", created.len()),
                        created_dirs: created,
                    })
                }
            }),
        )
        // ─────────────────────────────────────────────────────────────────────────────
        // M2: STATUT DE PROJET & BASCULE DE MODE DE VUE DUAL-VISION
        // ─────────────────────────────────────────────────────────────────────────────
        .route(
            "/api/project/status",
            axum::routing::get({
                let state = state_project_status.clone();
                move || {
                    let state = state.clone();
                    async move {
                        let status_resp = state.get_project_status().await;
                        axum::Json(status_resp)
                    }
                }
            }),
        )
        // ─────────────────────────────────────────────────────────────────────────────
        // M1: LIVE GIT DIFF & STATUS API
        // ─────────────────────────────────────────────────────────────────────────────
        .route(
            "/api/git/status",
            axum::routing::get({
                let state = state_git_status.clone();
                move || {
                    let state = state.clone();
                    async move {
                        // Zéro clone du graphe : git tourne hors-graphe (cache 3 s), puis la
                        // corrélation SAST se fait sous simple verrou de lecture.
                        axum::Json(state.git_status_cached().await)
                    }
                }
            }),
        )
        .route(
            "/api/view_mode",
            axum::routing::post({
                let state = state_view_mode.clone();
                move |axum::extract::Json(req): axum::extract::Json<api_routes::ViewModeRequest>| {
                    let state = state.clone();
                    async move {
                        use axum::response::IntoResponse;
                        match state.switch_view_mode(&req.mode).await {
                            Ok(graph) => (
                                axum::http::StatusCode::OK,
                                axum::Json(api_routes::ui_payload::build_payload(&graph)),
                            )
                                .into_response(),
                            Err(api_routes::ViewModeError::InvalidMode(err)) => (
                                axum::http::StatusCode::BAD_REQUEST,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": err
                                })),
                            )
                                .into_response(),
                            Err(api_routes::ViewModeError::GraphNotAvailable(err)) => (
                                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": err
                                })),
                            )
                                .into_response(),
                        }
                    }
                }
            }),
        )
        .route(
            "/api/analyze",
            axum::routing::post({
                let state = state_analyze.clone();
                move |axum::extract::Json(req): axum::extract::Json<AnalyzeRequest>| {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;

                        let raw = req.path.trim().trim_matches('"').trim_matches('\'');
                        let clean = raw.strip_prefix(r"\\?\").unwrap_or(raw);
                        let mut path = if clean.is_empty() || clean == "." {
                            state.project_root.read().await.clone()
                        } else {
                            fs::canonicalize(clean).unwrap_or_else(|_| PathBuf::from(&clean))
                        };

                        if !path.exists() {
                            return (
                                StatusCode::BAD_REQUEST,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Chemin introuvable : {}", clean)
                                })),
                            )
                                .into_response();
                        }
                        if path.is_file() {
                            if let Some(parent) = path.parent() {
                                path = parent.to_path_buf();
                            }
                        }

                        let active_graph = execute_project_pipeline(&state, path, req.exclusions).await;
                        (
                            StatusCode::OK,
                            axum::Json(api_routes::ui_payload::build_payload(&active_graph)),
                        )
                            .into_response()
                    }
                }
            })
            .get({
                let state = state_analyze_get.clone();
                move |axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>| {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;

                        let p_str = query.get("path").cloned().unwrap_or_default();
                        let raw = p_str.trim().trim_matches('"').trim_matches('\'');
                        let clean = raw.strip_prefix(r"\\?\").unwrap_or(raw);
                        let mut path = if clean.is_empty() || clean == "." {
                            state.project_root.read().await.clone()
                        } else {
                            fs::canonicalize(clean).unwrap_or_else(|_| PathBuf::from(&clean))
                        };

                        if !path.exists() {
                            return (
                                StatusCode::BAD_REQUEST,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Chemin introuvable : {}", clean)
                                })),
                            )
                                .into_response();
                        }
                        if path.is_file() {
                            if let Some(parent) = path.parent() {
                                path = parent.to_path_buf();
                            }
                        }

                        let active_graph = execute_project_pipeline(&state, path, None).await;
                        (
                            StatusCode::OK,
                            axum::Json(api_routes::ui_payload::build_payload(&active_graph)),
                        )
                            .into_response()
                    }
                }
            }),
        )
        .route(
            "/api/graph",
            axum::routing::get(move |axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>| {
                let state = state_graph.clone();
                async move {
                    use axum::response::IntoResponse;
                    let is_full = q
                        .get("full")
                        .map(|v| {
                            let t = v.trim();
                            t == "1" || t.eq_ignore_ascii_case("true")
                        })
                        .unwrap_or(false);
                    if is_full {
                        // Format historique complet (MCP, exports) : aretes en objets, aucun allegement.
                        let g = state.graph.read().await;
                        return axum::Json(g.clone()).into_response();
                    }
                    let is_mcp = q
                        .get("mcp")
                        .map(|v| {
                            let t = v.trim();
                            t == "1" || t.eq_ignore_ascii_case("true")
                        })
                        .unwrap_or(false);
                    if is_mcp {
                        let bytes = state.mcp_graph_json().await;
                        return (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            bytes.as_ref().clone(),
                        )
                            .into_response();
                    }
                    // UI : JSON compact et mis en cache par version (aretes en tableaux d'indices).
                    let bytes = state.ui_graph_json().await;
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        bytes.as_ref().clone(),
                    )
                        .into_response()
                }
            }),
        )
        .route(
            "/api/graph/version",
            axum::routing::get(move || {
                let state = state_graph_version.clone();
                async move {
                    let v = state.graph_version.load(std::sync::atomic::Ordering::SeqCst);
                    let vv = state.visual_plugins_version.load(std::sync::atomic::Ordering::SeqCst);
                    let fv = state.fs_version.load(std::sync::atomic::Ordering::SeqCst);
                    let changed = state.last_changed_files.read().await.clone();
                    axum::Json(serde_json::json!({
                        "version": v,
                        "visual_version": vv,
                        "fs_version": fv,
                        "changed_files": changed
                    }))
                }
            }),
        )
        .route(
            "/api/graph/events",
            axum::routing::get({
                let state = state_graph_events.clone();
                move || {
                    let state = state.clone();
                    async move {
                        use axum::response::sse::{Event, KeepAlive, Sse};
                        let rx = state.event_tx.subscribe();
                        let initial_event = api_routes::GraphWatchEvent {
                            version: state.graph_version.load(std::sync::atomic::Ordering::SeqCst),
                            visual_version: state
                                .visual_plugins_version
                                .load(std::sync::atomic::Ordering::SeqCst),
                            fs_version: state.fs_version.load(std::sync::atomic::Ordering::SeqCst),
                            changed_files: Vec::new(),
                            kind: "sync".to_string(),
                        };
                        let stream = futures_util::stream::unfold(
                            (rx, state, Some(initial_event)),
                            |(mut rx, state, pending_init)| async move {
                                if let Some(init_ev) = pending_init {
                                    let data = serde_json::to_string(&init_ev).unwrap_or_default();
                                    return Some((
                                        Ok::<Event, std::convert::Infallible>(
                                            Event::default().data(data),
                                        ),
                                        (rx, state, None),
                                    ));
                                }
                                loop {
                                    match rx.recv().await {
                                        Ok(ev) => {
                                            let data =
                                                serde_json::to_string(&ev).unwrap_or_default();
                                            return Some((
                                                Ok::<Event, std::convert::Infallible>(
                                                    Event::default().data(data),
                                                ),
                                                (rx, state, None),
                                            ));
                                        }
                                        Err(tokio::sync::broadcast::error::RecvError::Lagged(
                                            _,
                                        )) => {
                                            let sync_ev = api_routes::GraphWatchEvent {
                                                version: state
                                                    .graph_version
                                                    .load(std::sync::atomic::Ordering::SeqCst),
                                                visual_version: state
                                                    .visual_plugins_version
                                                    .load(std::sync::atomic::Ordering::SeqCst),
                                                fs_version: state
                                                    .fs_version
                                                    .load(std::sync::atomic::Ordering::SeqCst),
                                                changed_files: state
                                                    .last_changed_files
                                                    .read()
                                                    .await
                                                    .clone(),
                                                kind: "lag_resync".to_string(),
                                            };
                                            let data = serde_json::to_string(&sync_ev)
                                                .unwrap_or_default();
                                            return Some((
                                                Ok::<Event, std::convert::Infallible>(
                                                    Event::default().data(data),
                                                ),
                                                (rx, state, None),
                                            ));
                                        }
                                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                            return None;
                                        }
                                    }
                                }
                            },
                        );
                        Sse::new(stream).keep_alive(
                            KeepAlive::new()
                                .interval(std::time::Duration::from_secs(15))
                                .text("keep-alive"),
                        )
                    }
                }
            }),
        )
        .route(
            "/api/export",
            axum::routing::post(move |axum::extract::Json(req): axum::extract::Json<ExportRequest>| {
                let state = state_export.clone();
                async move {
                    let g = state.graph.read().await;
                    let p_root = state.project_root.read().await;
                    let target_dir = req.path.map(PathBuf::from).unwrap_or_else(|| p_root.clone());
                    let out_path = target_dir.join("aetherscope_viewer.html");
                    let p_type = *state.project_type.read().await;
                    let active_view = state.active_view_mode.read().await.clone();
                    let code_g = state.code_graph.read().await;
                    let vault_g = state.vault_graph.read().await;
                    let html = viewer::generate_modern_standalone_html(
                        code_g.as_ref().or(Some(&*g)),
                        vault_g.as_ref(),
                        p_type,
                        &active_view,
                    );
                    let _ = fs::write(&out_path, html);
                    axum::Json(ExportResponse {
                        status: "ok".to_string(),
                        viewer_path: out_path.to_string_lossy().to_string(),
                        total_nodes: g.nodes.len(),
                        total_edges: g.edges.len(),
                    })
                }
            }),
        )
        .route(
            "/api/save_doc",
            axum::routing::post(move |axum::extract::Json(req): axum::extract::Json<SaveDocRequest>| {
                let state = state_savedoc.clone();
                async move {
                    use axum::http::StatusCode;
                    use axum::response::IntoResponse;

                    let p_root = state.project_root.read().await.clone();
                    let canonical_p_root = match fs::canonicalize(&p_root) {
                        Ok(p) => p,
                        Err(e) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Root canonicalization failed: {}", e)
                                })),
                            )
                                .into_response();
                        }
                    };

                    // Validate client project_path if non-empty / non-dot
                    let proj_trimmed = req.project_path.trim().trim_matches('"').trim_matches('\'');
                    let proj_clean = proj_trimmed.strip_prefix(r"\\?\").unwrap_or(proj_trimmed);
                    if !proj_clean.is_empty() && proj_clean != "." {
                        let candidate_proj = PathBuf::from(proj_clean);
                        if let Ok(canon_cand) = fs::canonicalize(&candidate_proj) {
                            if !canon_cand.starts_with(&canonical_p_root) {
                                return (
                                    StatusCode::FORBIDDEN,
                                    axum::Json(serde_json::json!({
                                        "status": "error",
                                        "message": "project_path escapes designated project_root"
                                    })),
                                )
                                    .into_response();
                            }
                        } else if candidate_proj != p_root {
                            return (
                                StatusCode::BAD_REQUEST,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": "Invalid project_path"
                                })),
                            )
                                .into_response();
                        }
                    }

                    // Validate file_name lexically
                    let clean_file_name = match PathGuard::validate_client_relative_path(&req.file_name) {
                        Ok(p) => p,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    // Validate folder and construct clean relative candidate path
                    let clean_rel = if req.folder.trim().is_empty()
                        || req.folder.trim() == "root"
                        || req.folder.trim() == "."
                    {
                        clean_file_name
                    } else {
                        let clean_folder = match PathGuard::validate_client_relative_path(&req.folder) {
                            Ok(p) => p,
                            Err(e) => {
                                let (code, json_val) = security_error_to_status_and_json(&e);
                                return (code, axum::Json(json_val)).into_response();
                            }
                        };
                        clean_folder.join(clean_file_name)
                    };

                    // Validate sensitive file / secret blocking
                    if SecretGuard::is_secret_path(&clean_rel) {
                        return (
                            StatusCode::FORBIDDEN,
                            axum::Json(serde_json::json!({
                                "status": "error",
                                "message": format!("Access denied: Cannot create secret or sensitive file '{}'", clean_rel.display())
                            })),
                        )
                            .into_response();
                    }
                    if SecretMasker::contains_secret(&req.content) {
                        return (
                            StatusCode::FORBIDDEN,
                            axum::Json(serde_json::json!({
                                "status": "error",
                                "message": "Access denied: File content contains sensitive credentials or secrets prohibited by SecretMasker"
                            })),
                        )
                            .into_response();
                    }
                    if let Err(e) = PathGuard::validate_not_sensitive(&clean_rel) {
                        let (code, json_val) = security_error_to_status_and_json(&e);
                        return (code, axum::Json(json_val)).into_response();
                    }

                    // Resolve write target with ancestor canonicalization and jail containment
                    let guard = match PathGuard::new(&canonical_p_root) {
                        Ok(g) => g,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    let path = match guard.resolve_write_target(&clean_rel) {
                        Ok(p) => p,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    if let Some(parent) = path.parent() {
                        if let Err(e) = fs::create_dir_all(parent) {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Failed to create parent directory: {}", e)
                                })),
                            )
                                .into_response();
                        }
                    }

                    if let Err(e) = fs::write(&path, &req.content) {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(serde_json::json!({
                                "status": "error",
                                "message": format!("Failed to write file: {}", e)
                            })),
                        )
                            .into_response();
                    }

                    let mut blake3_hash = None;
                    let mut graph_opt = None;
                    if req.file_name.eq_ignore_ascii_case("README.md") {
                        if let Ok((_, h)) = sign_project_contracts(&canonical_p_root, Some(&req.folder)) {
                            blake3_hash = h;
                        }
                        let exclusions = state.custom_exclusions.read().await.clone();
                        let scanner = ProjectScanner::default()
                            .with_plugin_selection(state.plugin_selection.clone());
                        let updated_graph = scanner.scan_project_with_exclusions(&canonical_p_root, &exclusions);
                        {
                            let mut cg_guard = state.code_graph.write().await;
                            *cg_guard = Some(updated_graph.clone());
                            let mut g_guard = state.graph.write().await;
                            *g_guard = updated_graph.clone();
                        }
                        state.graph_version.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        graph_opt = Some(updated_graph);
                    }

                    (
                        StatusCode::OK,
                        axum::Json(SaveDocResponse {
                            status: "ok".to_string(),
                            saved_path: path.to_string_lossy().to_string(),
                            blake3_hash,
                            graph: graph_opt,
                        }),
                    )
                        .into_response()
                }
            }),
        )
        // Signature officielle des contrats BLAKE3 dans aether.lock.toml
        .route(
            "/api/contracts/sign",
            axum::routing::post(move |axum::extract::Json(req): axum::extract::Json<SignContractsRequest>| {
                let state = state_sign_contracts.clone();
                async move { handle_contracts_sign(&state, req).await }
            }),
        )
        // Modification directe d'un contrat (dossier ou fichier) depuis Aether + scellement BLAKE3
        .route(
            "/api/contracts/update",
            axum::routing::post(move |axum::extract::Json(req): axum::extract::Json<UpdateContractRequest>| {
                let state = state_update_contract.clone();
                async move { handle_contracts_update(&state, req).await }
            }),
        )
        // Pont IA Zero-Shell : Ã©criture de .aether/ACTIVE_TARGET.md et gÃ©nÃ©ration du paquet <aether_handshake version="2.0">
        .route(
            "/api/ai/target",
            axum::routing::post(move |axum::extract::Json(req): axum::extract::Json<AiTargetRequest>| {
                let state = state_ai_target.clone();
                async move {
                    use axum::http::StatusCode;
                    use axum::response::IntoResponse;

                    let p_root = state.project_root.read().await.clone();
                    if SecretGuard::is_secret_path(&req.symbol_id) {
                        return (
                            StatusCode::FORBIDDEN,
                            axum::Json(serde_json::json!({
                                "status": "error",
                                "message": format!("Access denied: Symbol/path '{}' is a protected secret file (.env, secrets, credentials)", req.symbol_id)
                            })),
                        )
                            .into_response();
                    }
                    let g = state.graph.read().await;

                    let sym_opt = g
                        .nodes
                        .iter()
                        .find(|n| {
                            n.id == req.symbol_id
                                || n.name == req.symbol_id
                                || n.file_path == req.symbol_id
                                || n.id.ends_with(&format!("::{}", req.symbol_id))
                        })
                        .cloned();

                    if let Some(sym) = sym_opt {
                        if SecretGuard::is_secret_path(&sym.file_path) {
                            return (
                                StatusCode::FORBIDDEN,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Access denied: Target file '{}' is a protected secret file (.env, secrets, credentials)", sym.file_path)
                                })),
                            )
                                .into_response();
                        }
                        let incoming_edges: Vec<&core_graph::edge::AffiliationEdge> = g
                            .edges
                            .iter()
                            .filter(|e| e.target == sym.id && e.relation != "contains")
                            .collect();
                        let outgoing_edges: Vec<&core_graph::edge::AffiliationEdge> = g
                            .edges
                            .iter()
                            .filter(|e| e.source == sym.id && e.relation != "contains")
                            .collect();

                        let categorized_in = core_graph::edge::CategorizedLiaisons::from_edges(&incoming_edges, &sym.id, true);
                        let categorized_out = core_graph::edge::CategorizedLiaisons::from_edges(&outgoing_edges, &sym.id, false);

                        let callers: Vec<String> = incoming_edges.iter().map(|e| e.source.clone()).collect();
                        let dependencies: Vec<String> = outgoing_edges.iter().map(|e| e.target.clone()).collect();

                        // Recherche du contrat README.md applicable au dossier ou fichier du symbole
                        let readme_path = {
                            let mut current = sym.folder.replace('\\', "/");
                            let mut found = None;
                            loop {
                                let candidate = if current.is_empty() || current == "root" || current == "." {
                                    p_root.join("README.md")
                                } else {
                                    p_root.join(&current).join("README.md")
                                };
                                if candidate.exists() {
                                    found = Some(candidate);
                                    break;
                                }
                                if current.is_empty() || current == "root" || current == "." {
                                    break;
                                }
                                if let Some(idx) = current.rfind('/') {
                                    current = current[..idx].to_string();
                                } else {
                                    current = "root".to_string();
                                }
                            }
                            found.unwrap_or_else(|| p_root.join("README.md"))
                        };

                        let contract = fs::read_to_string(&readme_path)
                            .ok()
                            .and_then(|c| ReadmeContract::parse(&sym.folder, &c).ok());

                        let _ = AuditWriter::write_active_target_categorized(
                            &p_root,
                            &sym,
                            &categorized_in,
                            &categorized_out,
                            contract.as_ref(),
                        );

                        let action_type = req.action_type.as_deref().unwrap_or("Target");
                        let handshake_xml = HandshakePacker::build_categorized_prompt(
                            action_type,
                            &sym,
                            &categorized_in,
                            &categorized_out,
                            contract.as_ref(),
                        );
                        let handshake_xml = SecretMasker::mask_text(&handshake_xml);

                        let active_target_path = p_root.join(".aether").join("ACTIVE_TARGET.md").to_string_lossy().to_string();

                        let mut doc_content = if !sym.docstring.is_empty() {
                            sym.docstring.clone()
                        } else if let Some(raw) = &sym.metadata.raw_content {
                            raw.clone()
                        } else {
                            String::new()
                        };

                        // Fallback lecture de commentaires sources au-dessus de la ligne du symbole
                        if doc_content.is_empty() && !sym.file_path.is_empty() && sym.line_number > 0 {
                            let src_path = p_root.join(&sym.file_path);
                            if let Ok(file_str) = fs::read_to_string(&src_path) {
                                let lines: Vec<&str> = file_str.lines().collect();
                                let target_idx = sym.line_number.saturating_sub(1);
                                let mut collected = Vec::new();
                                for i in (0..target_idx).rev().take(30) {
                                    if let Some(line) = lines.get(i) {
                                        let trimmed = line.trim();
                                        if trimmed.is_empty() {
                                            if collected.is_empty() { continue; } else { break; }
                                        }
                                        if trimmed.starts_with("#[") || trimmed.starts_with("#![") || trimmed == "]" || (trimmed.starts_with('@') && !trimmed.starts_with("@param") && !trimmed.starts_with("@return")) {
                                            continue;
                                        }
                                        if trimmed.starts_with("//") {
                                            collected.push(trimmed.trim_start_matches('/').trim().to_string());
                                        } else if trimmed.starts_with('#') {
                                            collected.push(trimmed.trim_start_matches('#').trim().to_string());
                                        } else if trimmed.ends_with("*/") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                                            collected.push(trimmed.trim_matches(|c| c == '/' || c == '*').trim().to_string());
                                        } else {
                                            break;
                                        }
                                    }
                                }
                                if !collected.is_empty() {
                                    collected.reverse();
                                    doc_content = collected.join("\n");
                                }
                            }
                        }

                        let doc_display = if doc_content.is_empty() {
                            "*(Aucun commentaire AST direct dÃ©tectÃ©)*".to_string()
                        } else {
                            doc_content.clone()
                        };

                        let callers_md = categorized_in.to_compact_markdown("amont", 4);
                        let deps_md = categorized_out.to_compact_markdown("aval", 4);

                        let formatted_doc_and_liaisons = format!(
                            "# ðŸŽ¯ Cible : `{}`\n- **Fichier :** `{}:{}`\n- **Architecture :** Galaxie `{}` | Couche `{}` | StÃ©rÃ©otype `{}`\n\n## ðŸ“– DOCUMENTATION & SPÃ‰CIFICATIONS AST :\n{}\n\n## ðŸ“¥ FLUX AMONT / APPELANTS (Total: {}):\n{}\n## ðŸ“¤ FLUX AVAL / DÃ‰PENDANCES & LIAISONS (Total: {}):\n{}\n## ðŸ”’ CONTRAT DU MODULE (`{}`):\n- Imports autorisÃ©s : `{:?}`\n- Imports INTERDITS : `{:?}`\n- Lignes max : {}\n- Exigences EARS : {}",
                            sym.name,
                            sym.file_path,
                            sym.line_number,
                            sym.galaxy,
                            sym.layer,
                            sym.stereotype,
                            doc_display,
                            categorized_in.total(),
                            callers_md,
                            categorized_out.total(),
                            deps_md,
                            sym.folder,
                            contract.as_ref().map(|c| &c.frontmatter.allowed_imports).unwrap_or(&vec![]),
                            contract.as_ref().map(|c| &c.frontmatter.forbidden_imports).unwrap_or(&vec![]),
                            contract.as_ref().map(|c| c.effective_max_lines(&sym.file_path)).or(sym.metadata.max_lines_limit).unwrap_or(300),
                            contract.as_ref().map(|c| c.ears_requirements.len()).unwrap_or(sym.metadata.ears_count)
                        );

                        axum::Json(AiTargetResponse {
                            status: "ok".to_string(),
                            active_target_path,
                            handshake_xml,
                            blake3_hash: sym.metadata.blake3_hash.or_else(|| contract.as_ref().map(|c| c.blake3_hash.clone())),
                            lock_verified: sym.metadata.lock_verified,
                            ears_count: contract.as_ref().map(|c| c.ears_requirements.len()).unwrap_or(sym.metadata.ears_count),
                            symbol_name: Some(sym.name.clone()),
                            file_path: Some(format!("{}:{}", sym.file_path, sym.line_number)),
                            layer: Some(sym.layer.clone()),
                            galaxy: Some(sym.galaxy.clone()),
                            docstring: if doc_content.is_empty() { None } else { Some(doc_content) },
                            callers,
                            dependencies,
                            categorized_incoming: Some(categorized_in),
                            categorized_outgoing: Some(categorized_out),
                            formatted_doc_and_liaisons: Some(formatted_doc_and_liaisons),
                        })
                        .into_response()
                    } else {
                        axum::Json(AiTargetResponse {
                            status: "not_found".to_string(),
                            active_target_path: String::new(),
                            handshake_xml: String::new(),
                            blake3_hash: None,
                            lock_verified: None,
                            ears_count: 0,
                            symbol_name: None,
                            file_path: None,
                            layer: None,
                            galaxy: None,
                            docstring: None,
                            callers: vec![],
                            dependencies: vec![],
                            categorized_incoming: None,
                            categorized_outgoing: None,
                            formatted_doc_and_liaisons: None,
                        })
                        .into_response()
                    }
                }
            }),
        )
        // Télémétrie IA Multi-Agents Simultanés (uniquement agents connectés avec ping < 5 min)
        .route(
            "/api/ai/telemetry",
            axum::routing::get({
                let state = state_telemetry.clone();
                move || async move {
                    let now_secs = now_unix_secs();
                    let is_empty = state.active_agents.read().await.is_empty();
                    if is_empty {
                        let p_root = state.project_root.read().await.clone();
                        state.reload_telemetry_cache(&p_root).await;
                    }
                    let mut agents_map = state.active_agents.write().await;
                    agents_map.retain(|_, ag| is_agent_ping_fresh(ag.timestamp, now_secs));
                    let mut agents: Vec<AiTelemetryEvent> = agents_map.values().cloned().collect();
                    agents.sort_by_key(|b| std::cmp::Reverse(b.timestamp));
                    drop(agents_map);

                    let fresh_telemetry = {
                        let mut t_guard = state.telemetry.write().await;
                        if let Some(ref ev) = *t_guard {
                            if !is_agent_ping_fresh(ev.timestamp, now_secs) {
                                *t_guard = agents.first().cloned();
                            }
                        }
                        t_guard.clone()
                    };

                    let history = state.telemetry_history.read().await.clone();
                    axum::Json(serde_json::json!({
                        "telemetry": fresh_telemetry,
                        "agents": agents,
                        "history": history
                    }))
                }
            })
            .post({
                let state = state_telemetry.clone();
                move |axum::extract::Json(mut event): axum::extract::Json<AiTelemetryEvent>| async move {
                    if event.timestamp == 0 {
                        event.timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                    } else if event.timestamp > 1_000_000_000_000 {
                        event.timestamp /= 1000;
                    }
                    let agent_key = event
                        .agent_id
                        .clone()
                        .filter(|s| !s.trim().is_empty())
                        .or_else(|| event.agent_name.clone().filter(|s| !s.trim().is_empty()))
                        .unwrap_or_else(|| "primary-agent".to_string());
                    if event.agent_id.as_deref().map(str::trim).unwrap_or("").is_empty() {
                        event.agent_id = Some(agent_key.clone());
                    }
                    if event.agent_name.as_deref().map(str::trim).unwrap_or("").is_empty() {
                        event.agent_name = Some(agent_key);
                    }
                    let recorded = state.record_telemetry(event).await;
                    axum::Json(serde_json::json!({ "status": "ok", "event": recorded }))
                }
            })
            .delete({
                let state = state_telemetry.clone();
                move || async move {
                    state.clear_telemetry().await;
                    axum::Json(serde_json::json!({ "status": "ok" }))
                }
            }),
        )
        // Chat IA local
        .route(
            "/api/ai/chat",
            axum::routing::get({
                let state = state_chat.clone();
                move || async move {
                    let msgs = state.chat_messages.read().await;
                    let last_is_user = msgs.last().map(|m| m.sender == "user").unwrap_or(false);
                    let agent_status = if last_is_user { "thinking" } else { "ready" };
                    axum::Json(ChatMessagesResponse {
                        messages: msgs.clone(),
                        agent_status: agent_status.to_string(),
                    })
                }
            })
            .post({
                let state = state_chat.clone();
                move |axum::extract::Json(req): axum::extract::Json<SendChatMessageRequest>| async move {
                    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                    let resolved_color = if req.agent_id.is_some() || req.agent_name.is_some() || req.color.is_some() {
                        let aid = req.agent_id.as_deref().or(req.agent_name.as_deref()).unwrap_or("primary-agent");
                        Some(crate::api_routes::assign_agent_color(aid, req.agent_name.as_deref(), req.color.as_deref()))
                    } else {
                        None
                    };
                    let msg = AiChatMessage {
                        id: format!("msg_{}", now_ms),
                        sender: req.sender.unwrap_or_else(|| "user".to_string()),
                        text: req.text.clone(),
                        target_symbol: req.target_symbol.clone(),
                        timestamp: now_ms,
                        agent_id: req.agent_id.clone(),
                        agent_name: req.agent_name.clone(),
                        recipient: req.recipient,
                        color: resolved_color.clone(),
                    };
                    let mut msgs = state.chat_messages.write().await;
                    msgs.push(msg.clone());
                    drop(msgs);

                    // Persister le message dans .aether/CHAT_INBOX.md pour réveil et lecture IA zero-token
                    let p_root = state.project_root.read().await.clone();
                    let aether_dir = p_root.join(".aether");
                    let _ = fs::create_dir_all(&aether_dir);
                    let inbox_file = aether_dir.join("CHAT_INBOX.md");
                    if msg.sender == "user" {
                        let inbox_content = format!(
                            "# 📩 AetherScope Chat Inbox (En attente de réponse IA)\n\n- **Date :** {}\n- **Expéditeur :** {}\n- **Cible :** {}\n- **Statut :** PENDING_AI_RESPONSE\n\n### Message utilisateur :\n{}\n\n---\n> *Répondre via l'outil MCP `aetherscope_chat(action: \"send\", text: \"...\")` ou directement dans le copilote Antigravity.*\n",
                            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                            msg.sender,
                            msg.target_symbol.as_deref().unwrap_or("Global"),
                            msg.text
                        );
                        let _ = fs::write(&inbox_file, inbox_content);
                    } else {
                        let inbox_content = format!(
                            "# 📩 AetherScope Chat Inbox (Traité)\n\n- **Dernière réponse IA :** {}\n- **Par :** {}\n- **Statut :** ANSWERED\n\n> Le message précédent a reçu une réponse de l'IA.\n",
                            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                            msg.sender
                        );
                        let _ = fs::write(&inbox_file, inbox_content);
                    }

                    if let Some(ref sym) = req.target_symbol {
                        if !sym.trim().is_empty() && (req.agent_id.is_some() || msg.sender != "user") {
                            let _ = state.record_telemetry(AiTelemetryEvent {
                                target: sym.trim().to_string(),
                                action: "Chat / Hand-off".to_string(),
                                details: req.text.chars().take(120).collect(),
                                timestamp: now_ms / 1000,
                                agent_id: req.agent_id,
                                agent_name: req.agent_name,
                                color: resolved_color,
                            }).await;
                        }
                    }
                    axum::Json(serde_json::json!({ "status": "ok", "message": msg }))
                }
            }),
        )
        .route(
            "/api/ai/chat/clear",
            axum::routing::post({
                let state = state_chat.clone();
                move || async move {
                    let mut msgs = state.chat_messages.write().await;
                    msgs.clear();
                    let p_root = state.project_root.read().await.clone();
                    let _ = fs::remove_file(p_root.join(".aether").join("CHAT_INBOX.md"));
                    axum::Json(serde_json::json!({ "status": "ok" }))
                }
            }),
        )
        .route(
            "/api/ai/status",
            axum::routing::get(|| async { axum::Json(serde_json::json!({ "status": "idle" })) }),
        )
        .route(
            "/api/ai/cancel",
            axum::routing::post({
                let state = state_ai_cancel.clone();
                move || async move {
                    let mut t = state.telemetry.write().await;
                    *t = None;
                    let mut msgs = state.chat_messages.write().await;
                    if let Some(last) = msgs.last() {
                        if last.sender == "user" {
                            let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                            msgs.push(AiChatMessage {
                                id: format!("msg_{}", now_ms),
                                sender: "ai".to_string(),
                                text: "âš ï¸ RequÃªte interrompue par l'utilisateur.".to_string(),
                                target_symbol: None,
                                timestamp: now_ms,
                                ..Default::default()
                            });
                        }
                    }
                    axum::Json(serde_json::json!({ "status": "ok", "message": "RequÃªte IA annulÃ©e" }))
                }
            }),
        )
        .route(
            "/api/ai/new_session",
            axum::routing::post({
                let state = state_ai_session.clone();
                move || async move {
                    let mut msgs = state.chat_messages.write().await;
                    msgs.clear();
                    drop(msgs);
                    state.clear_telemetry().await;
                    axum::Json(serde_json::json!({ "status": "ok", "message": "Nouvelle session démarrée" }))
                }
            }),
        )
        .route(
            "/api/ai/launch_cli",
            axum::routing::post({
                let state = state_ai_cli.clone();
                move |axum::extract::Json(req): axum::extract::Json<LaunchCliRequest>| {
                    let state = state.clone();
                    async move {
                        let tool = req.tool.unwrap_or_else(|| "gemini".to_string());
                        let p_root = state.project_root.read().await.clone();
                        let rel_file = req.prompt.as_deref().unwrap_or("").trim();
                        let resolved_target = if !rel_file.is_empty() {
                            PathGuard::validate_client_relative_path(rel_file)
                                .ok()
                                .and_then(|clean_rel| {
                                    PathGuard::new(&p_root)
                                        .ok()
                                        .and_then(|g| g.resolve_write_target(&clean_rel).ok())
                                })
                                .unwrap_or_else(|| p_root.clone())
                        } else {
                            p_root.clone()
                        };
                        let clean_target = resolved_target
                            .to_string_lossy()
                            .trim_start_matches(r"\\?\")
                            .to_string();
                        if tool.eq_ignore_ascii_case("notepad") {
                            let _ = std::process::Command::new("notepad.exe")
                                .arg(&clean_target)
                                .spawn();
                        } else if tool.eq_ignore_ascii_case("vscode") || tool.eq_ignore_ascii_case("code") {
                            let line_suffix = req.project_path.as_deref().unwrap_or("1:1");
                            let goto_arg = format!("{}:{}", clean_target, line_suffix);
                            if std::process::Command::new("code.cmd")
                                .arg("--goto")
                                .arg(&goto_arg)
                                .spawn()
                                .is_err()
                            {
                                let _ = std::process::Command::new("code")
                                    .arg("--goto")
                                    .arg(&goto_arg)
                                    .spawn();
                            }
                        }
                        axum::Json(serde_json::json!({
                            "status": "ok",
                            "message": format!("Terminal CLI {} initialisÃ©", tool),
                            "tool": tool,
                            "project_path": req.project_path,
                            "prompt": req.prompt
                        }))
                    }
                }
            }),
        )
        .route(
            "/api/ai/system_prompt",
            axum::routing::get({
                let state = state_sysprompt.clone();
                move || async move {
                    let p_root = state.project_root.read().await;
                    let proj_name = p_root.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "Project".to_string());
                    
                    let stack_str = AuditWriter::detect_project_stack(&p_root);
                    let mut prompt = AuditWriter::generate_optimized_system_prompt(&p_root, &proj_name, stack_str, server_port);
                    if let Ok(custom_rules) = fs::read_to_string(p_root.join("AETHER_AI_RULES.md")) {
                        if !custom_rules.trim().is_empty() && !prompt.contains(custom_rules.trim()) {
                            prompt.push_str("\n\n");
                            prompt.push_str(&custom_rules);
                        }
                    }
                    axum::Json(serde_json::json!({
                        "status": "ok",
                        "project_name": proj_name,
                        "project_path": p_root.to_string_lossy(),
                        "stack": stack_str,
                        "system_prompt": prompt
                    }))
                }
            }),
        )
        // Gestionnaire de Tâches & Quêtes (Model & User)
        .route(
            "/api/tasks",
            axum::routing::get({
                let state = state_tasks.clone();
                move || async move {
                    let p_root = state.project_root.read().await;
                    let tasks = ai_file_bridge::TaskManager::list_tasks(&p_root);
                    axum::Json(serde_json::json!({ "status": "ok", "tasks": tasks }))
                }
            })
            .post({
                let state = state_tasks.clone();
                move |axum::extract::Json(req): axum::extract::Json<CreateTaskApiRequest>| async move {
                    let p_root = state.project_root.read().await.clone();
                    let kind = req.kind.as_deref().map(ai_file_bridge::TaskKind::from_str_loose).unwrap_or_default();
                    let author = req.author.as_deref().unwrap_or("user");
                    let resolved_color = if req.agent_id.is_some() || req.agent_name.is_some() || req.color.is_some() {
                        let aid = req.agent_id.as_deref().or(req.agent_name.as_deref()).unwrap_or(author);
                        Some(crate::api_routes::assign_agent_color(aid, req.agent_name.as_deref(), req.color.as_deref()))
                    } else if author != "user" {
                        Some(crate::api_routes::assign_agent_color(author, Some(author), None))
                    } else {
                        None
                    };
                    match ai_file_bridge::TaskManager::create_task_with_agent(
                        &p_root,
                        &req.title,
                        kind,
                        req.target_symbol.as_deref(),
                        req.target_file.as_deref(),
                        author,
                        req.priority.as_deref(),
                        req.initial_readme.as_deref(),
                        req.agent_id.as_deref(),
                        req.agent_name.as_deref(),
                        resolved_color.as_deref(),
                    ) {
                        Ok(task) => {
                            if let Some(target) = task.target_symbol.clone().or_else(|| task.target_file.clone()) {
                                if task.agent_id.is_some() || task.author != "user" {
                                    let _ = state.record_telemetry(AiTelemetryEvent {
                                        target,
                                        action: "Création de Tâche".to_string(),
                                        details: format!("Tâche créée : {}", task.title),
                                        timestamp: 0,
                                        agent_id: task.agent_id.clone().or_else(|| Some(task.author.clone())),
                                        agent_name: task.agent_name.clone().or_else(|| Some(task.author.clone())),
                                        color: task.color.clone(),
                                    }).await;
                                }
                            }
                            axum::Json(serde_json::json!({ "status": "ok", "task": task }))
                        }
                        Err(e) => axum::Json(serde_json::json!({ "status": "error", "message": format!("{}", e) })),
                    }
                }
            }),
        )
        .route(
            "/api/tasks/update",
            axum::routing::post({
                let state = state_tasks.clone();
                move |axum::extract::Json(req): axum::extract::Json<UpdateTaskApiRequest>| async move {
                    let p_root = state.project_root.read().await.clone();
                    let status = req.status.as_deref().map(ai_file_bridge::TaskStatus::from_str_loose);
                    let resolved_color = if req.agent_id.is_some() || req.agent_name.is_some() || req.color.is_some() {
                        let aid = req.agent_id.as_deref().or(req.agent_name.as_deref()).unwrap_or("primary-agent");
                        Some(crate::api_routes::assign_agent_color(aid, req.agent_name.as_deref(), req.color.as_deref()))
                    } else {
                        None
                    };
                    match ai_file_bridge::TaskManager::update_task_with_meta(
                        &p_root,
                        &req.task_id,
                        status,
                        req.progress,
                        req.progress_note.as_deref(),
                        req.full_readme.as_deref(),
                        req.title.as_deref(),
                        req.target_symbol.as_deref(),
                        req.target_file.as_deref(),
                        req.priority.as_deref(),
                        req.agent_id.as_deref(),
                        req.agent_name.as_deref(),
                        resolved_color.as_deref(),
                    ) {
                        Ok(Some(task)) => {
                            if let Some(target) = task.target_symbol.clone().or_else(|| task.target_file.clone()) {
                                if req.agent_id.is_some() || req.agent_name.is_some() || task.agent_id.is_some() || task.author != "user" {
                                    let _ = state.record_telemetry(AiTelemetryEvent {
                                        target,
                                        action: format!("Suivi Tâche ({}%)", task.progress),
                                        details: req.progress_note.clone().unwrap_or_else(|| format!("Statut : {} — {}", task.status.as_str(), task.title)),
                                        timestamp: 0,
                                        agent_id: req.agent_id.or_else(|| task.agent_id.clone()).or_else(|| Some(task.author.clone())),
                                        agent_name: req.agent_name.or_else(|| task.agent_name.clone()).or_else(|| Some(task.author.clone())),
                                        color: resolved_color.or_else(|| task.color.clone()),
                                    }).await;
                                }
                            }
                            axum::Json(serde_json::json!({ "status": "ok", "task": task }))
                        }
                        Ok(None) => axum::Json(serde_json::json!({ "status": "not_found", "message": "Tâche introuvable" })),
                        Err(e) => axum::Json(serde_json::json!({ "status": "error", "message": format!("{}", e) })),
                    }
                }
            }),
        )
        .route(
            "/api/tasks/delete",
            axum::routing::post({
                let state = state_tasks.clone();
                move |axum::extract::Json(req): axum::extract::Json<DeleteTaskApiRequest>| async move {
                    let p_root = state.project_root.read().await;
                    match ai_file_bridge::TaskManager::delete_task(&p_root, &req.task_id) {
                        Ok(deleted) => axum::Json(serde_json::json!({ "status": "ok", "deleted": deleted })),
                        Err(e) => axum::Json(serde_json::json!({ "status": "error", "message": format!("{}", e) })),
                    }
                }
            }),
        )
        // Création de fichier assistée par l'Inspecteur / IA
        .route(
            "/api/ai/create_file",
            axum::routing::post(move |axum::extract::Json(req): axum::extract::Json<CreateFileRequest>| {
                let state = state_create_file.clone();
                async move {
                    use axum::http::StatusCode;
                    use axum::response::IntoResponse;

                    let p_root = state.project_root.read().await.clone();
                    let canonical_p_root = match fs::canonicalize(&p_root) {
                        Ok(p) => p,
                        Err(e) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Root canonicalization failed: {}", e)
                                })),
                            )
                                .into_response();
                        }
                    };

                    // Validate client project_path if non-empty / non-dot
                    let proj_trimmed = req.project_path.trim().trim_matches('"').trim_matches('\'');
                    let proj_clean = proj_trimmed.strip_prefix(r"\\?\").unwrap_or(proj_trimmed);
                    if !proj_clean.is_empty() && proj_clean != "." {
                        let candidate_proj = PathBuf::from(proj_clean);
                        if let Ok(canon_cand) = fs::canonicalize(&candidate_proj) {
                            if !canon_cand.starts_with(&canonical_p_root) {
                                return (
                                    StatusCode::FORBIDDEN,
                                    axum::Json(serde_json::json!({
                                        "status": "error",
                                        "message": "project_path escapes designated project_root"
                                    })),
                                )
                                    .into_response();
                            }
                        } else if candidate_proj != p_root {
                            return (
                                StatusCode::BAD_REQUEST,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": "Invalid project_path"
                                })),
                            )
                                .into_response();
                        }
                    }

                    // Validate file_path lexically
                    let clean_rel = match PathGuard::validate_client_relative_path(&req.file_path) {
                        Ok(p) => p,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    // Validate sensitive file / secret blocking
                    if SecretGuard::is_secret_path(&clean_rel) {
                        return (
                            StatusCode::FORBIDDEN,
                            axum::Json(serde_json::json!({
                                "status": "error",
                                "message": format!("Access denied: Cannot create secret or sensitive file '{}'", clean_rel.display())
                            })),
                        )
                            .into_response();
                    }
                    if SecretMasker::contains_secret(&req.content) {
                        return (
                            StatusCode::FORBIDDEN,
                            axum::Json(serde_json::json!({
                                "status": "error",
                                "message": "Access denied: File content contains sensitive credentials or secrets prohibited by SecretMasker"
                            })),
                        )
                            .into_response();
                    }
                    if let Err(e) = PathGuard::validate_not_sensitive(&clean_rel) {
                        let (code, json_val) = security_error_to_status_and_json(&e);
                        return (code, axum::Json(json_val)).into_response();
                    }

                    // Resolve write target with ancestor canonicalization
                    let guard = match PathGuard::new(&canonical_p_root) {
                        Ok(g) => g,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    let target_path = match guard.resolve_write_target(&clean_rel) {
                        Ok(p) => p,
                        Err(e) => {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }
                    };

                    if let Some(parent) = target_path.parent() {
                        if let Err(e) = fs::create_dir_all(parent) {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Failed to create parent directory: {}", e)
                                })),
                            )
                                .into_response();
                        }
                    }

                    if let Err(e) = fs::write(&target_path, &req.content) {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(serde_json::json!({
                                "status": "error",
                                "message": format!("Failed to write file: {}", e)
                            })),
                        )
                            .into_response();
                    }

                    let exclusions = state.custom_exclusions.read().await.clone();
                    let scanner = ProjectScanner::default()
                        .with_plugin_selection(state.plugin_selection.clone());
                    let new_graph = scanner.scan_project_with_exclusions(&p_root, &exclusions);
                    {
                        let mut cg_guard = state.code_graph.write().await;
                        *cg_guard = Some(new_graph.clone());
                    }
                    let mut g_guard = state.graph.write().await;
                    *g_guard = new_graph.clone();
                    state.graph_version.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                    let created_symbol = req.file_path.replace(['/', '\\'], "::");
                    (
                        StatusCode::OK,
                        axum::Json(CreateFileResponse {
                            status: "ok".to_string(),
                            file_path: req.file_path,
                            created_symbol,
                            graph: new_graph.clone(),
                            data: new_graph,
                        }),
                    )
                        .into_response()
                }
            }),
        )
        // Chargement à la demande de fichier / README (Lazy-loading pour booster les perfs)
        .route(
            "/api/file_content",
            axum::routing::get({
                let state = state_file_content.clone();
                move |axum::extract::Query(query): axum::extract::Query<api_routes::FileContentQuery>| {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;

                        let rel_path = query.path.unwrap_or_default().trim().to_string();

                        // 1. Lexical client-relative validation
                        let clean_rel = match PathGuard::validate_client_relative_path(&rel_path) {
                            Ok(p) => p,
                            Err(e) => {
                                let (code, json_val) = security_error_to_status_and_json(&e);
                                return (code, axum::Json(json_val)).into_response();
                            }
                        };

                        // 2. Sensitive file check
                        if SecretGuard::is_secret_path(&clean_rel) {
                            return (
                                StatusCode::FORBIDDEN,
                                axum::Json(serde_json::json!({
                                    "status": "error",
                                    "message": format!("Access denied: Sensitive file '{}' is protected against exposure (.env, secrets, credentials)", clean_rel.display())
                                })),
                            )
                                .into_response();
                        }
                        if let Err(e) = PathGuard::validate_not_sensitive(&clean_rel) {
                            let (code, json_val) = security_error_to_status_and_json(&e);
                            return (code, axum::Json(json_val)).into_response();
                        }

                        // 3. Confinement resolution and read via PathGuard
                        let p_root = state.project_root.read().await.clone();
                        let guard = match PathGuard::new(&p_root) {
                            Ok(g) => g,
                            Err(e) => {
                                let (code, json_val) = security_error_to_status_and_json(&e);
                                return (code, axum::Json(json_val)).into_response();
                            }
                        };

                        let mut read_res = guard.read_to_string(&clean_rel);
                        if read_res.is_err() {
                            for attempt in 1..=20 {
                                tokio::time::sleep(tokio::time::Duration::from_millis(attempt * 2)).await;
                                read_res = guard.read_to_string(&clean_rel);
                                if read_res.is_ok() {
                                    break;
                                }
                            }
                        }

                        match read_res {
                            Ok(content) => {
                                let is_raw = query.raw.unwrap_or(false);
                                let final_content = if is_raw {
                                    content
                                } else {
                                    SecretMasker::mask_text(&content)
                                };
                                (
                                    StatusCode::OK,
                                    axum::Json(serde_json::json!({
                                        "status": "ok",
                                        "path": rel_path,
                                        "content": final_content
                                    })),
                                )
                                    .into_response()
                            }
                            Err(e) => {
                                let (code, mut json_val) = security_error_to_status_and_json(&e);
                                if let Some(obj) = json_val.as_object_mut() {
                                    obj.insert("path".to_string(), serde_json::Value::String(rel_path.clone()));
                                }
                                (code, axum::Json(json_val)).into_response()
                            }
                        }
                    }
                }
            }),
        )
        // ─────────────────────────────────────────────────────────────────────────────
        // M1: SAUVEGARDE DE FICHIER SOURCE (IDE CTRL+S)
        // ─────────────────────────────────────────────────────────────────────────────
        .route(
            "/api/save_file",
            axum::routing::post({
                let state = state_save_file.clone();
                move |axum::extract::Json(req): axum::extract::Json<api_routes::SaveFileRequest>| {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;

                        match state.save_file(&req.file_path, &req.content).await {
                            Ok(resp) => (StatusCode::OK, axum::Json(resp)).into_response(),
                            Err(e) => {
                                let (code, json_val) = security_error_to_status_and_json(&e);
                                (code, axum::Json(json_val)).into_response()
                            }
                        }
                    }
                }
            }),
        )
        // ─────────────────────────────────────────────────────────────────────────────
        // M1: ARBORESCENCE DU PROJET (IDE FILE TREE)
        // ─────────────────────────────────────────────────────────────────────────────
        .route(
            "/api/files",
            axum::routing::get({
                let state = state_files.clone();
                move || {
                    let state = state.clone();
                    async move {
                        use axum::http::StatusCode;
                        use axum::response::IntoResponse;

                        let files = state.list_files().await;
                        (
                            StatusCode::OK,
                            axum::Json(api_routes::ProjectFilesResponse {
                                status: "ok".to_string(),
                                files,
                            }),
                        )
                            .into_response()
                    }
                }
            }),
        )
        .route(
            "/api/bounty/scope",
            axum::routing::get({
                let state = state_file_content.clone();
                move || {
                    let state = state.clone();
                    async move {
                        let p_root = state.project_root.read().await.clone();
                        let g = state.graph.read().await.clone();
                        let (cfg, recs) = crate::mcp::load_or_recommend_bounty_scope(&p_root, &g);
                        axum::Json(serde_json::json!({
                            "status": "ok",
                            "scope": cfg,
                            "recommendations": recs
                        }))
                    }
                }
            })
            .post({
                let state = state_file_content.clone();
                move |axum::extract::Json(payload): axum::extract::Json<serde_json::Value>| {
                    let state = state.clone();
                    async move {
                        let p_root = state.project_root.read().await.clone();
                        let g = state.graph.read().await.clone();
                        let recs = crate::mcp::compute_scope_recommendations(&g);
                        let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("set");
                        let updated_by = payload
                            .get("updated_by")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let rationale = payload
                            .get("rationale")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let cfg = if action == "auto_recommend" {
                            crate::mcp::build_recommended_scope_config(&recs, updated_by, rationale)
                        } else {
                            let in_scope: Vec<String> = payload
                                .get("in_scope")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default();
                            let out_of_scope: Vec<String> = payload
                                .get("out_of_scope")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default();
                            let mode = payload
                                .get("mode")
                                .and_then(|v| v.as_str())
                                .unwrap_or("manual")
                                .to_string();
                            crate::mcp::BountyScopeConfig {
                                in_scope,
                                out_of_scope,
                                mode,
                                updated_by: Some(updated_by.unwrap_or_else(|| "User / MCP".to_string())),
                                rationale,
                                timestamp: now_ms,
                            }
                        };
                        crate::mcp::save_bounty_scope(&p_root, &cfg);
                        axum::Json(serde_json::json!({
                            "status": "ok",
                            "scope": cfg,
                            "recommendations": recs
                        }))
                    }
                }
            }),
        )
        // Flux brut binaire pour images, SVG et médias (PNG, SVG, JPG, WebP, etc.)
        .route(
            "/api/raw_file",
            axum::routing::get({
                let state = state_raw_file.clone();
                move |axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>| {
                    let state = state.clone();
                    async move {
                        use axum::http::{header, StatusCode};
                        use axum::response::IntoResponse;

                        let rel_path = query.get("path").cloned().unwrap_or_default();
                        if rel_path.trim().is_empty() {
                            return (StatusCode::BAD_REQUEST, "Chemin manquant").into_response();
                        }

                        // 1. Lexical client-relative validation
                        let clean_rel = match PathGuard::validate_client_relative_path(&rel_path) {
                            Ok(p) => p,
                            Err(e) => {
                                let (code, body) = security_error_to_status_and_json(&e);
                                return (code, body.to_string()).into_response();
                            }
                        };

                        // 2. Allowed extension whitelisting
                        let ext_str = match PathGuard::validate_raw_extension(&clean_rel) {
                            Ok(ext) => ext,
                            Err(e) => {
                                let (code, body) = security_error_to_status_and_json(&e);
                                return (code, body.to_string()).into_response();
                            }
                        };

                        // 3. Sensitive file validation
                        if let Err(e) = PathGuard::validate_not_sensitive(&clean_rel) {
                            let (code, body) = security_error_to_status_and_json(&e);
                            return (code, body.to_string()).into_response();
                        }

                        // 4. Confinement resolution and read via PathGuard
                        let p_root = state.project_root.read().await.clone();
                        let guard = match PathGuard::new(&p_root) {
                            Ok(g) => g,
                            Err(e) => {
                                let (code, body) = security_error_to_status_and_json(&e);
                                return (code, body.to_string()).into_response();
                            }
                        };

                        match guard.read_bytes(&clean_rel) {
                            Ok(bytes) => {
                                let content_type = match ext_str {
                                    "png" => "image/png",
                                    "jpg" | "jpeg" => "image/jpeg",
                                    "gif" => "image/gif",
                                    "svg" => "image/svg+xml",
                                    "webp" => "image/webp",
                                    "ico" => "image/x-icon",
                                    "bmp" => "image/bmp",
                                    "tiff" => "image/tiff",
                                    "pdf" => "application/pdf",
                                    "json" => "application/json",
                                    "md" | "markdown" | "txt" => "text/plain; charset=utf-8",
                                    "csv" => "text/csv; charset=utf-8",
                                    _ => return (StatusCode::BAD_REQUEST, "Extension non autorisée").into_response(),
                                };
                                (
                                    StatusCode::OK,
                                    [(header::CONTENT_TYPE, content_type)],
                                    bytes,
                                )
                                    .into_response()
                            }
                            Err(e) => {
                                let (code, body) = security_error_to_status_and_json(&e);
                                (code, body.to_string()).into_response()
                            }
                        }
                    }
                }
            }),
        )
        .route(
            "/api/settings",
            axum::routing::get({
                let state = state_settings.clone();
                move || async move {
                    let exclusions = state.custom_exclusions.read().await.clone();
                    let catalogue = security_linter::SecurityLinter::get_supported_cve_rules();
                    let saved_active = state.active_cve_rules.read().await.clone();
                    let active_rules: Vec<String> = saved_active
                        .unwrap_or_else(|| catalogue.iter().map(|r| r.rule_id.clone()).collect());
                    let ignored_cwes = state.ignored_cwes.read().await.clone();
                    let ui_settings = state.saved_ui_settings.read().await.clone();
                    let show_alerts = *state.show_alerts.read().await;
                    let show_cwe_bubbles = *state.show_cwe_bubbles.read().await;
                    let show_cwe_titles = *state.show_cwe_titles.read().await;
                    let show_folder_titles = *state.show_folder_titles.read().await;
                    let show_file_titles = *state.show_file_titles.read().await;
                    let low_memory_mode = *state.low_memory_mode.read().await;
                    let active_visual_plugin = state.active_visual_plugin.read().await.clone();
                    axum::Json(SettingsPayload {
                        exclusions,
                        active_cve_rules: Some(active_rules),
                        ignored_cwes: Some(ignored_cwes),
                        cve_catalogue: Some(catalogue),
                        mcp_binary_path: resolve_mcp_binary_path(),
                        show_alerts,
                        show_cwe_bubbles,
                        show_cwe_titles,
                        show_folder_titles,
                        show_file_titles,
                        low_memory_mode,
                        active_visual_plugin,
                        ui_settings,
                        rescan: None,
                    })
                }
            })
            .post({
                let state = state_settings.clone();
                move |axum::extract::Json(payload): axum::extract::Json<SettingsPayload>| async move {
                    let prev_exclusions = state.custom_exclusions.read().await.clone();
                    let prev_active_rules = state.active_cve_rules.read().await.clone();
                    let prev_ignored_cwes = state.ignored_cwes.read().await.clone();

                    let exclusions_changed = !payload.exclusions.is_empty() && payload.exclusions != prev_exclusions;
                    if !payload.exclusions.is_empty() || payload.rescan == Some(true) {
                        let mut excl_guard = state.custom_exclusions.write().await;
                        *excl_guard = payload.exclusions.clone();
                    }
                    let active_rules_changed = payload.active_cve_rules.is_some()
                        && payload.active_cve_rules != prev_active_rules;
                    if let Some(ref rules) = payload.active_cve_rules {
                        let mut cve_guard = state.active_cve_rules.write().await;
                        *cve_guard = Some(rules.clone());
                    }
                    let ignored_changed = payload.ignored_cwes.is_some()
                        && payload.ignored_cwes.as_deref() != Some(prev_ignored_cwes.as_slice());
                    if let Some(ref ignored) = payload.ignored_cwes {
                        let mut ign_guard = state.ignored_cwes.write().await;
                        *ign_guard = ignored.clone();
                    }
                    if payload.ui_settings.is_some() {
                        let mut ui_guard = state.saved_ui_settings.write().await;
                        *ui_guard = payload.ui_settings.clone();
                    }
                    if let Some(v) = payload.show_alerts {
                        let mut g = state.show_alerts.write().await;
                        *g = Some(v);
                    }
                    if let Some(v) = payload.show_cwe_bubbles {
                        let mut g = state.show_cwe_bubbles.write().await;
                        *g = Some(v);
                    }
                    if let Some(v) = payload.show_cwe_titles {
                        let mut g = state.show_cwe_titles.write().await;
                        *g = Some(v);
                    }
                    if let Some(v) = payload.show_folder_titles {
                        let mut g = state.show_folder_titles.write().await;
                        *g = Some(v);
                    }
                    if let Some(v) = payload.show_file_titles {
                        let mut g = state.show_file_titles.write().await;
                        *g = Some(v);
                    }
                    if let Some(v) = payload.low_memory_mode {
                        let mut g = state.low_memory_mode.write().await;
                        *g = Some(v);
                    }
                    if let Some(ref vp) = payload.active_visual_plugin {
                        let mut g = state.active_visual_plugin.write().await;
                        *g = Some(vp.clone());
                    }

                    // Persist the merged settings so partial POSTs (e.g. ignore CWE) never wipe UI display toggles
                    let merged_exclusions = state.custom_exclusions.read().await.clone();
                    let active_opt = state.active_cve_rules.read().await.clone();
                    let ignored_cwes = state.ignored_cwes.read().await.clone();
                    let merged_payload = SettingsPayload {
                        exclusions: merged_exclusions.clone(),
                        active_cve_rules: active_opt.clone(),
                        ignored_cwes: Some(ignored_cwes.clone()),
                        cve_catalogue: None,
                        mcp_binary_path: None,
                        show_alerts: *state.show_alerts.read().await,
                        show_cwe_bubbles: *state.show_cwe_bubbles.read().await,
                        show_cwe_titles: *state.show_cwe_titles.read().await,
                        show_folder_titles: *state.show_folder_titles.read().await,
                        show_file_titles: *state.show_file_titles.read().await,
                        low_memory_mode: *state.low_memory_mode.read().await,
                        active_visual_plugin: state.active_visual_plugin.read().await.clone(),
                        ui_settings: state.saved_ui_settings.read().await.clone(),
                        rescan: None,
                    };
                    let p_root = state.project_root.read().await.clone();
                    save_project_settings(&p_root, &merged_payload);

                    let needs_rescan = payload.rescan == Some(true)
                        || exclusions_changed
                        || active_rules_changed
                        || ignored_changed;

                    let (total_nodes, total_edges) = if needs_rescan {
                        let scanner = ProjectScanner::default()
                            .with_plugin_selection(state.plugin_selection.clone());
                        let mut new_graph = scanner.scan_project_with_exclusions(&p_root, &merged_exclusions);
                        apply_settings_filters_to_graph(
                            &mut new_graph,
                            active_opt.as_deref(),
                            &ignored_cwes,
                        );
                        let tn = new_graph.nodes.len();
                        let te = new_graph.edges.len();
                        {
                            let mut cg_guard = state.code_graph.write().await;
                            *cg_guard = Some(new_graph.clone());
                        }
                        let mut g_guard = state.graph.write().await;
                        *g_guard = new_graph;
                        state.graph_version.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        (tn, te)
                    } else {
                        let g_guard = state.graph.read().await;
                        (g_guard.nodes.len(), g_guard.edges.len())
                    };

                    let catalogue = security_linter::SecurityLinter::get_supported_cve_rules();
                    let active_resp = active_opt.unwrap_or_else(|| catalogue.iter().map(|r| r.rule_id.clone()).collect());
                    axum::Json(serde_json::json!({
                        "status": "ok",
                        "exclusions": merged_exclusions,
                        "active_cve_rules": active_resp,
                        "ignored_cwes": ignored_cwes,
                        "cve_catalogue": catalogue,
                        "total_nodes": total_nodes,
                        "total_edges": total_edges
                    }))
                }
            }),
        )
        .route(
            "/api/surface_scan",
            axum::routing::post({
                let state = shared_state.clone();
                move |axum::extract::Json(req): axum::extract::Json<surface_scanner::SurfaceScanRequest>| {
                    let state = state.clone();
                    async move {
                        let report = surface_scanner::run_surface_scan(req).await;
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        {
                            let mut t_guard = state.telemetry.write().await;
                            *t_guard = Some(AiTelemetryEvent {
                                target: report.host.clone(),
                                action: format!("Scan Surface ({})", report.grade),
                                details: format!(
                                    "Score {}/100 | {} IP(s) | {} port(s) ouverts | {} alerte(s)",
                                    report.security_score,
                                    report.resolved_ips.len(),
                                    report.open_ports.iter().filter(|p| p.open).count(),
                                    report.findings.len()
                                ),
                                timestamp: now_ms,
                                ..Default::default()
                            });
                        }
                        axum::Json(report)
                    }
                }
            }),
        )
        .route("/api/health", axum::routing::get(|| async { "{\"status\":\"ok\",\"engine\":\"aether-v2\"}" }))
        .merge(
            axum::Router::new()
                .route("/api/plugins", axum::routing::get(plugin_routes::get_plugins_handler))
                .route("/api/plugins/toggle", axum::routing::post(plugin_routes::toggle_plugin_handler))
                .route("/api/plugins/test", axum::routing::post(plugin_routes::test_plugins_handler))
                .route("/api/plugins/init_bundle", axum::routing::post(plugin_routes::init_bundle_handler))
                .route("/api/plugins/import_semgrep", axum::routing::post(plugin_routes::import_semgrep_handler))
                .route("/api/plugins/upsert", axum::routing::post(plugin_routes::upsert_plugin_rule_handler))
                .route("/api/plugins/delete", axum::routing::post(plugin_routes::delete_plugin_handler))
                .route("/api/visual_plugins", axum::routing::get(visual_plugin_routes::get_visual_plugins_handler))
                .route("/api/visual_plugins/activate", axum::routing::post(visual_plugin_routes::activate_visual_plugin_handler))
                .route("/api/visual_plugins/upsert", axum::routing::post(visual_plugin_routes::upsert_visual_plugin_handler))
                .route("/api/visual_plugins/delete", axum::routing::post(visual_plugin_routes::delete_visual_plugin_handler))
                .with_state(shared_state.clone()),
        )
        .route(
            "/favicon.ico",
            axum::routing::get(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        // Pas de CORS permissif : le cockpit est servi par ce mÃªme serveur (same-origin) et le pont MCP
        // n'envoie pas d'Origin. Toute requÃªte cross-origin / DNS-rebinding est refusÃ©e par le garde.
        .layer(axum::middleware::from_fn_with_state(
            local_guard::LocalGuard::new(args.port),
            local_guard::enforce_local_only,
        ));

    let addr = format!("127.0.0.1:{}", args.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    axum::serve(listener, app).await?;
    Ok(())
}

async fn resolve_confined_contract_root(
    state: &AppState,
    project_path: Option<&str>,
) -> Result<PathBuf, axum::response::Response> {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let p_root = state.project_root.read().await.clone();
    let canonical_p_root = fs::canonicalize(&p_root).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "status": "error",
                "error": "internal_error",
                "message": format!("Root canonicalization failed: {}", e)
            })),
        )
            .into_response()
    })?;

    if let Some(raw_proj) = project_path {
        let proj_trimmed = raw_proj.trim().trim_matches('"').trim_matches('\'');
        let proj_clean = proj_trimmed.strip_prefix(r"\\?\").unwrap_or(proj_trimmed);
        if !proj_clean.is_empty() && proj_clean != "." {
            let candidate_proj = PathBuf::from(proj_clean);
            if let Ok(canon_cand) = fs::canonicalize(&candidate_proj) {
                if !canon_cand.starts_with(&canonical_p_root) {
                    return Err((
                        StatusCode::FORBIDDEN,
                        axum::Json(serde_json::json!({
                            "status": "error",
                            "error": "forbidden",
                            "message": "project_path escapes designated project_root"
                        })),
                    )
                        .into_response());
                }
            } else if candidate_proj != p_root {
                return Err((
                    StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({
                        "status": "error",
                        "error": "bad_request",
                        "message": "Invalid project_path"
                    })),
                )
                    .into_response());
            }
        }
    }

    Ok(canonical_p_root)
}

fn validate_contract_inputs(
    folder: Option<&str>,
    file_path: Option<&str>,
) -> Result<(), axum::response::Response> {
    use axum::response::IntoResponse;

    if let Some(raw_f) = folder {
        let trimmed = raw_f.trim().trim_end_matches(['/', '\\']);
        if !trimmed.is_empty() && trimmed != "." && trimmed != "root" {
            let clean_folder = PathGuard::validate_client_relative_path(trimmed).map_err(|e| {
                let (code, json_val) = security_error_to_status_and_json(&e);
                (code, axum::Json(json_val)).into_response()
            })?;
            PathGuard::validate_not_sensitive(&clean_folder).map_err(|e| {
                let (code, json_val) = security_error_to_status_and_json(&e);
                (code, axum::Json(json_val)).into_response()
            })?;
        }
    }

    if let Some(raw_fp) = file_path {
        let trimmed = raw_fp.trim();
        if !trimmed.is_empty() {
            let clean_fp = PathGuard::validate_client_relative_path(trimmed).map_err(|e| {
                let (code, json_val) = security_error_to_status_and_json(&e);
                (code, axum::Json(json_val)).into_response()
            })?;
            PathGuard::validate_not_sensitive(&clean_fp).map_err(|e| {
                let (code, json_val) = security_error_to_status_and_json(&e);
                (code, axum::Json(json_val)).into_response()
            })?;
        }
    }

    Ok(())
}

async fn rescan_and_sync_after_contracts(
    state: &AppState,
    canonical_root: &Path,
    changed_files: Vec<String>,
) -> Result<core_graph::graph::AetherGraph, axum::response::Response> {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let exclusions = state.custom_exclusions.read().await.clone();
    let active_rules = state.active_cve_rules.read().await.clone();
    let ignored_cwes = state.ignored_cwes.read().await.clone();
    let sel = state.plugin_selection.clone();
    let scan_root = canonical_root.to_path_buf();

    let mut new_graph = tokio::task::spawn_blocking(move || {
        let scanner = ProjectScanner::default().with_plugin_selection(sel);
        scanner.scan_project_with_exclusions(&scan_root, &exclusions)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "status": "error",
                "error": "internal_error",
                "message": format!("Contract rescan failed: {}", e)
            })),
        )
            .into_response()
    })?;

    apply_settings_filters_to_graph(&mut new_graph, active_rules.as_deref(), &ignored_cwes);

    {
        let mut cg_guard = state.code_graph.write().await;
        *cg_guard = Some(new_graph.clone());
    }
    let mode = state.get_active_view_mode().await;
    if mode != "vault" && mode != "vault-notes" {
        let mut g_guard = state.graph.write().await;
        *g_guard = new_graph.clone();
    }
    *state.ui_graph_cache.write().await = None;
    state
        .graph_version
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    state.notify_graph_change(changed_files, "contracts");

    Ok(new_graph)
}

async fn handle_contracts_sign(
    state: &Arc<AppState>,
    req: SignContractsRequest,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let canonical_root = match resolve_confined_contract_root(state, req.project_path.as_deref()).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_contract_inputs(req.folder.as_deref(), None) {
        return resp;
    }

    let (signed_count, blake3_hash) = match sign_project_contracts(&canonical_root, req.folder.as_deref()) {
        Ok(res) => res,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "status": "error",
                    "error": "bad_request",
                    "message": e
                })),
            )
                .into_response();
        }
    };

    let new_graph = match rescan_and_sync_after_contracts(
        state,
        &canonical_root,
        vec!["aether.lock.toml".to_string()],
    )
    .await
    {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    (
        StatusCode::OK,
        axum::Json(SignContractsResponse {
            status: "ok".to_string(),
            message: format!(
                "{} contrat(s) README.md signé(s) avec BLAKE3 dans aether.lock.toml",
                signed_count
            ),
            signed_count,
            blake3_hash,
            graph: new_graph,
        }),
    )
        .into_response()
}

async fn handle_contracts_update(
    state: &Arc<AppState>,
    req: UpdateContractRequest,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let canonical_root = match resolve_confined_contract_root(state, req.project_path.as_deref()).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_contract_inputs(req.folder.as_deref(), req.file_path.as_deref()) {
        return resp;
    }

    match update_contract_rules(&canonical_root, &req) {
        Ok((contract_path, blake3_hash, file_blake3_hash, effective_max_lines)) => {
            let new_graph = match rescan_and_sync_after_contracts(
                state,
                &canonical_root,
                vec![contract_path.clone(), "aether.lock.toml".to_string()],
            )
            .await
            {
                Ok(g) => g,
                Err(resp) => return resp,
            };

            (
                StatusCode::OK,
                axum::Json(UpdateContractResponse {
                    status: "ok".to_string(),
                    message: format!(
                        "Contrat '{}' mis a jour (max {} lignes) et scelle BLAKE3",
                        contract_path, effective_max_lines
                    ),
                    contract_path,
                    blake3_hash,
                    file_blake3_hash,
                    effective_max_lines,
                    graph: new_graph,
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "status": "error",
                "error": "bad_request",
                "message": e,
                "contract_path": req.folder.unwrap_or_else(|| "README.md".to_string()),
                "blake3_hash": "",
                "effective_max_lines": 300
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod contracts_route_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn spawn_contracts_test_server(
        root: PathBuf,
        view_mode: &str,
    ) -> (u16, tokio::task::JoinHandle<()>, Arc<AppState>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let port = listener.local_addr().expect("local addr").port();

        let code_g = core_graph::graph::AetherGraph::new("CodeContractsTest");
        let vault_g = core_graph::graph::AetherGraph::new("VaultContractsTest");
        let initial_g = if view_mode == "vault" || view_mode == "vault-notes" {
            vault_g.clone()
        } else {
            code_g.clone()
        };

        let state = Arc::new(AppState::new(
            initial_g,
            root,
            obsidian_vault::DetectedProjectType::Mixed,
            view_mode.to_string(),
            Some(code_g),
            Some(vault_g),
            None,
        ));

        let s_sign = state.clone();
        let s_update = state.clone();
        let app = axum::Router::new()
            .route(
                "/api/contracts/sign",
                axum::routing::post(move |axum::extract::Json(req): axum::extract::Json<SignContractsRequest>| {
                    let st = s_sign.clone();
                    async move { handle_contracts_sign(&st, req).await }
                }),
            )
            .route(
                "/api/contracts/update",
                axum::routing::post(move |axum::extract::Json(req): axum::extract::Json<UpdateContractRequest>| {
                    let st = s_update.clone();
                    async move { handle_contracts_update(&st, req).await }
                }),
            );

        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        (port, handle, state)
    }

    async fn post_json(port: u16, path: &str, body: &serde_json::Value) -> (u16, serde_json::Value) {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .expect("connect test server");
        let body_str = serde_json::to_string(body).expect("serialize body");
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            path,
            port,
            body_str.len(),
            body_str
        );
        stream.write_all(req.as_bytes()).await.expect("write req");

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read resp");
        let raw = String::from_utf8_lossy(&buf);
        let mut parts = raw.splitn(2, "\r\n\r\n");
        let headers = parts.next().unwrap_or("");
        let body_part = parts.next().unwrap_or("");
        let status: u16 = headers
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let val: serde_json::Value = serde_json::from_str(body_part).unwrap_or(serde_json::Value::Null);
        (status, val)
    }

    #[tokio::test]
    async fn test_contracts_sign_valid_cache_invalidation_and_readme_preservation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        fs::create_dir_all(root.join("crates/sub")).unwrap();

        let original_readme = "---\nid: root\nlayer: core\nmax_lines_per_file: 420\n---\n# Root\n\n# Keep exact bytes!\n";
        let sub_readme = "---\nid: sub\nlayer: domain\nmax_lines_per_file: 250\n---\n# Sub\n";
        fs::write(root.join("README.md"), original_readme).unwrap();
        fs::write(root.join("crates/sub/README.md"), sub_readme).unwrap();
        fs::write(root.join("crates/sub/lib.rs"), "pub fn ok() {}\n").unwrap();

        let (port, handle, state) = spawn_contracts_test_server(root.clone(), "code").await;
        let mut rx = state.event_tx.subscribe();

        // Populate ui_graph_cache first so we can verify invalidation
        let _ = state.ui_graph_json().await;
        assert!(state.ui_graph_cache.read().await.is_some());
        let ver_before = state.graph_version.load(std::sync::atomic::Ordering::SeqCst);
        let fs_before = state.fs_version.load(std::sync::atomic::Ordering::SeqCst);

        // 1. Sign with project_path = None, folder = Some(".")
        let (status, json) = post_json(port, "/api/contracts/sign", &serde_json::json!({ "folder": "." })).await;
        assert_eq!(status, 200);
        assert_eq!(json["status"], "ok");
        assert_eq!(json["signed_count"], 1);
        assert_eq!(fs::read_to_string(root.join("README.md")).unwrap(), original_readme);
        assert!(root.join("aether.lock.toml").exists());
        assert!(state.ui_graph_cache.read().await.is_none(), "ui_graph_cache must be invalidated");
        assert_eq!(state.graph_version.load(std::sync::atomic::Ordering::SeqCst), ver_before + 1);
        assert_eq!(state.fs_version.load(std::sync::atomic::Ordering::SeqCst), fs_before + 1);
        let ev = rx.recv().await.expect("SSE watch event");
        assert_eq!(ev.kind, "contracts");

        // 2. Sign with project_path = temp_root, folder = "crates/sub"
        let (status2, json2) = post_json(
            port,
            "/api/contracts/sign",
            &serde_json::json!({
                "project_path": root.to_string_lossy(),
                "folder": "crates/sub"
            }),
        )
        .await;
        assert_eq!(status2, 200);
        assert_eq!(json2["signed_count"], 1);
        assert_eq!(fs::read_to_string(root.join("crates/sub/README.md")).unwrap(), sub_readme);

        handle.abort();
    }

    #[tokio::test]
    async fn test_contracts_sign_preserves_vault_graph_in_vault_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        fs::write(root.join("README.md"), "---\nid: root\nlayer: core\nmax_lines_per_file: 300\n---\n# Root\n").unwrap();

        let (port, handle, state) = spawn_contracts_test_server(root, "vault").await;
        let (status, json) = post_json(port, "/api/contracts/sign", &serde_json::json!({ "folder": "root" })).await;
        assert_eq!(status, 200);
        assert_eq!(json["status"], "ok");
        assert_eq!(state.graph.read().await.project_name, "VaultContractsTest");
        assert!(state.code_graph.read().await.is_some());

        handle.abort();
    }

    #[tokio::test]
    async fn test_contracts_routes_reject_traversal_and_sensitive_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        let root = dir.path().to_path_buf();
        fs::write(root.join("README.md"), "---\nid: root\nlayer: core\nmax_lines_per_file: 300\n---\n# Root\n").unwrap();

        let (port, handle, _state) = spawn_contracts_test_server(root, "code").await;

        // 1. Existing outside project_path -> 403 FORBIDDEN
        let (s1, _) = post_json(
            port,
            "/api/contracts/sign",
            &serde_json::json!({ "project_path": outside.path().to_string_lossy() }),
        )
        .await;
        assert_eq!(s1, 403);

        // 2. Non-existent relative escaping project_path -> 400 BAD_REQUEST
        let (s2, _) = post_json(
            port,
            "/api/contracts/update",
            &serde_json::json!({ "project_path": "../outside_nonexistent" }),
        )
        .await;
        assert_eq!(s2, 400);

        // 3. Traversal folder -> 400 BAD_REQUEST
        let (s3, _) = post_json(
            port,
            "/api/contracts/update",
            &serde_json::json!({ "folder": "../../evil", "max_lines_per_file": 100 }),
        )
        .await;
        assert_eq!(s3, 400);
        assert!(!outside.path().join("README.md").exists());

        // 4. Traversal file_path -> 400 BAD_REQUEST
        let (s4, _) = post_json(
            port,
            "/api/contracts/update",
            &serde_json::json!({ "folder": ".", "file_path": "../../etc/passwd", "file_max_lines": 50 }),
        )
        .await;
        assert_eq!(s4, 400);

        // 5. Sensitive folder (.git) -> 403 FORBIDDEN
        let (s5, _) = post_json(
            port,
            "/api/contracts/sign",
            &serde_json::json!({ "folder": ".git" }),
        )
        .await;
        assert_eq!(s5, 403);

        // 6. Sensitive file (.env) -> 403 FORBIDDEN
        let (s6, _) = post_json(
            port,
            "/api/contracts/update",
            &serde_json::json!({ "folder": ".", "file_path": ".env", "file_max_lines": 50 }),
        )
        .await;
        assert_eq!(s6, 403);

        handle.abort();
    }

    #[tokio::test]
    async fn test_contracts_update_valid_invalidates_cache_and_emits_event() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        fs::create_dir_all(root.join("crates/sub")).unwrap();
        fs::write(root.join("crates/sub/lib.rs"), "pub fn run() {}\n").unwrap();

        let (port, handle, state) = spawn_contracts_test_server(root.clone(), "code").await;
        let mut rx = state.event_tx.subscribe();
        let _ = state.ui_graph_json().await;
        assert!(state.ui_graph_cache.read().await.is_some());

        let (status, json) = post_json(
            port,
            "/api/contracts/update",
            &serde_json::json!({
                "project_path": ".",
                "folder": "crates/sub",
                "file_path": "crates/sub/lib.rs",
                "max_lines_per_file": 333
            }),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(json["status"], "ok");
        assert_eq!(json["contract_path"], "crates/sub/README.md");
        assert_eq!(json["effective_max_lines"], 333);
        assert!(root.join("crates/sub/README.md").exists());
        assert!(root.join("aether.lock.toml").exists());
        assert!(state.ui_graph_cache.read().await.is_none());
        let ev = rx.recv().await.expect("SSE watch event");
        assert_eq!(ev.kind, "contracts");

        handle.abort();
    }
}
