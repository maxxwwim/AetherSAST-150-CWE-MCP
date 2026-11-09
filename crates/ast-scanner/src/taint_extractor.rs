use core_graph::dataflow::{
    DataflowEdge, DataflowGraph, SanitizerRule, SinkKind, SourceKind, SsaVar,
    TaintSink, TaintSource, TaintStepKind,
};
use core_graph::graph::AetherGraph;
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

macro_rules! static_regex {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new($pattern).expect("Invalid static regex"))
        }
    };
}

static_regex!(
    re_php_func_decl,
    r#"(?:public\s+|protected\s+|private\s+|static\s+)*function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)"#
);
static_regex!(
    re_js_func_decl,
    r#"(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)"#
);
static_regex!(
    re_js_arrow_decl,
    r#"(?:export\s+)?(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"#
);
static_regex!(
    re_py_func_decl,
    r#"(?:async\s+)?def\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)"#
);
static_regex!(
    re_rs_func_decl,
    r#"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([a-zA-Z0-9_]+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)"#
);
static_regex!(
    re_zig_func_decl,
    r#"(?:pub\s+)?(?:export\s+|extern\s+|inline\s+)?fn\s+([a-zA-Z0-9_]+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)"#
);
static_regex!(
    re_cs_func_decl,
    r#"(?:(?:public|protected|private|internal|static|virtual|override|abstract|sealed|async|partial|extern)\s+)+(?:[A-Za-z0-9_<>\[\]?,\s]+\s+)+([A-Za-z0-9_]+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)"#
);

static_regex!(
    re_php_var,
    r#"(\$[a-zA-Z_][a-zA-Z0-9_]*)"#
);
static_regex!(
    re_ident,
    r#"\b([a-zA-Z_][a-zA-Z0-9_]*)\b"#
);

static_regex!(
    re_php_assign,
    r#"(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;]+);"#
);
static_regex!(
    re_general_assign,
    r#"(?:let|const|var)?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;]+);?"#
);

static_regex!(
    re_return_stmt,
    r#"return\s+([^;]+);?"#
);

static_regex!(
    re_call_expr,
    r#"([a-zA-Z0-9_.:->]+)\s*\(([^)]*)\)"#
);

/// Discovered Call Site during AST parsing
#[derive(Debug, Clone)]
struct CallSite {
    caller: String,
    callee: String,
    line: usize,
    arg_vars: Vec<SsaVar>,
    lhs_var: Option<SsaVar>,
}

/// Function signature metadata
#[derive(Debug, Clone)]
struct FunctionMeta {
    name: String,
    file_path: String,
    line: usize,
    params: Vec<String>,
    return_var: Option<SsaVar>,
}

/// Multi-language AST Taint & SSA Dataflow Extractor
pub struct TaintExtractor;

impl TaintExtractor {
    /// Extracts SSA DataflowGraph from a single source file.
    pub fn extract_from_source(
        file_path: &str,
        content: &str,
        custom_sanitizers: &[SanitizerRule],
    ) -> DataflowGraph {
        Self::extract_multi(&[(file_path, content)], custom_sanitizers)
    }

    /// Extracts SSA DataflowGraph across multiple files with cross-file inter-procedural linking.
    pub fn extract_multi(
        files: &[(&str, &str)],
        custom_sanitizers: &[SanitizerRule],
    ) -> DataflowGraph {
        let mut dfg = DataflowGraph::new();
        for r in custom_sanitizers {
            dfg.add_sanitizer(r.clone());
        }

        let mut functions: HashMap<String, FunctionMeta> = HashMap::new();
        let mut call_sites: Vec<CallSite> = Vec::new();

        // Pass 1: Intra-procedural SSA extraction & def-use per file
        for &(file_path, content) in files {
            Self::extract_file_intra(file_path, content, &mut dfg, &mut functions, &mut call_sites);
        }

        // Pass 2: Inter-procedural propagation (caller arguments -> callee params, return -> caller LHS)
        Self::link_inter_procedural(&mut dfg, &functions, &call_sites);

        dfg
    }

    /// Enriches an existing AetherGraph by extracting dataflow and linking it with CVE anomalies.
    pub fn enrich_aether_graph(graph: &mut AetherGraph, custom_sanitizers: &[SanitizerRule]) {
        let mut files = Vec::new();
        for node in &graph.nodes {
            if node.is_file {
                if let Some(ref content) = node.metadata.raw_content {
                    files.push((node.file_path.as_str(), content.as_str()));
                }
            }
        }

        if !files.is_empty() {
            let dfg = Self::extract_multi(&files, custom_sanitizers);
            graph.dataflow_graph = Some(dfg);
            graph.compute_dataflow_taint(custom_sanitizers);
        }
    }

    /// Intra-procedural scan: extracts variables, versions, assignments, sources, and sinks within functions.
    fn extract_file_intra(
        file_path: &str,
        content: &str,
        dfg: &mut DataflowGraph,
        functions: &mut HashMap<String, FunctionMeta>,
        call_sites: &mut Vec<CallSite>,
    ) {
        let is_php = file_path.ends_with(".php") || file_path.ends_with(".phtml");
        let is_js = file_path.ends_with(".js") || file_path.ends_with(".ts") || file_path.ends_with(".jsx") || file_path.ends_with(".tsx");
        let is_py = file_path.ends_with(".py");
        let is_rs = file_path.ends_with(".rs");
        let is_zig = file_path.ends_with(".zig");
        let is_cs = file_path.ends_with(".cs");

        let lines: Vec<&str> = content.lines().collect();

        let mut current_scope = "global".to_string();
        let mut scope_versions: HashMap<String, usize> = HashMap::new();
        let mut brace_depth: i32 = 0;
        let mut in_function = false;

        for (line_idx, raw_line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = raw_line.trim();

            if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }

            // Track block depth
            let open_braces = trimmed.chars().filter(|&c| c == '{').count() as i32;
            let close_braces = trimmed.chars().filter(|&c| c == '}').count() as i32;
            brace_depth += open_braces - close_braces;

            // Detect Function Definition
            let mut detected_func = None;
            let mut func_params = Vec::new();

            if is_php {
                if let Some(caps) = re_php_func_decl().captures(trimmed) {
                    let fn_name = caps[1].to_string();
                    let raw_params = &caps[2];
                    for p_cap in re_php_var().captures_iter(raw_params) {
                        func_params.push(p_cap[1].to_string());
                    }
                    detected_func = Some(fn_name);
                }
            } else if is_js {
                if let Some(caps) = re_js_func_decl().captures(trimmed).or_else(|| re_js_arrow_decl().captures(trimmed)) {
                    let fn_name = caps[1].to_string();
                    for p in caps[2].split(',') {
                        let clean = p.trim().split(':').next().unwrap_or("").trim();
                        if !clean.is_empty() && clean != "this" {
                            func_params.push(clean.to_string());
                        }
                    }
                    detected_func = Some(fn_name);
                }
            } else if is_py {
                if let Some(caps) = re_py_func_decl().captures(trimmed) {
                    let fn_name = caps[1].to_string();
                    for p in caps[2].split(',') {
                        let clean = p.trim().split(':').next().unwrap_or("").split('=').next().unwrap_or("").trim();
                        if !clean.is_empty() && clean != "self" && clean != "cls" {
                            func_params.push(clean.to_string());
                        }
                    }
                    detected_func = Some(fn_name);
                }
            } else if is_rs {
                if let Some(caps) = re_rs_func_decl().captures(trimmed) {
                    let fn_name = caps[1].to_string();
                    for p in caps[2].split(',') {
                        let clean = p.trim().split(':').next().unwrap_or("").trim().trim_start_matches("mut ").trim();
                        if !clean.is_empty() && !clean.contains("self") {
                            func_params.push(clean.to_string());
                        }
                    }
                    detected_func = Some(fn_name);
                }
            } else if is_zig {
                if let Some(caps) = re_zig_func_decl().captures(trimmed) {
                    let fn_name = caps[1].to_string();
                    for p in caps[2].split(',') {
                        let clean = p.trim().split(':').next().unwrap_or("").trim();
                        if !clean.is_empty() && clean != "self" && !clean.contains("self") {
                            func_params.push(clean.to_string());
                        }
                    }
                    detected_func = Some(fn_name);
                }
            } else if is_cs {
                if let Some(caps) = re_cs_func_decl().captures(trimmed) {
                    let fn_name = caps[1].to_string();
                    for p in caps[2].split(',') {
                        let trimmed_p = p.trim();
                        let parts: Vec<&str> = trimmed_p.split_whitespace().collect();
                        if let Some(last_ident) = parts.last() {
                            let clean = last_ident.trim_start_matches('@').trim();
                            if !clean.is_empty() && clean != "this" {
                                func_params.push(clean.to_string());
                            }
                        }
                    }
                    detected_func = Some(fn_name);
                }
            }

            if let Some(fn_name) = detected_func {
                current_scope = fn_name.clone();
                scope_versions.clear();
                in_function = true;

                // Register parameters as SSA version 0
                for p in &func_params {
                    scope_versions.insert(p.clone(), 0);
                    let var = SsaVar::new(p.clone(), 0, current_scope.clone(), line_num).with_file(file_path);
                    dfg.add_var(var);
                }

                functions.insert(
                    fn_name.clone(),
                    FunctionMeta {
                        name: fn_name,
                        file_path: file_path.to_string(),
                        line: line_num,
                        params: func_params,
                        return_var: None,
                    },
                );
            }

            if in_function && brace_depth <= 0 && (open_braces > 0 || close_braces > 0) {
                in_function = false;
                current_scope = "global".to_string();
            }

            // Detect Source (HTTP input, query params, etc.)
            let is_http_source = trimmed.contains("$_GET")
                || trimmed.contains("$_POST")
                || trimmed.contains("$_REQUEST")
                || trimmed.contains("$_COOKIE")
                || trimmed.contains("req.query")
                || trimmed.contains("req.body")
                || trimmed.contains("req.params")
                || trimmed.contains("request.args")
                || trimmed.contains("request.form");

            // Detect Assignment
            let mut assign_parsed: Option<(String, String)> = None;
            if is_php {
                if let Some(caps) = re_php_assign().captures(trimmed) {
                    assign_parsed = Some((caps[1].to_string(), caps[2].to_string()));
                }
            } else if let Some(caps) = re_general_assign().captures(trimmed) {
                let lhs = caps[1].to_string();
                if !lhs.is_empty() && lhs != "if" && lhs != "while" && lhs != "return" {
                    assign_parsed = Some((lhs, caps[2].to_string()));
                }
            }

            if let Some((lhs, rhs)) = assign_parsed {
                // Determine new SSA version for LHS
                let current_ver = scope_versions.get(&lhs).copied().unwrap_or(0);
                let new_ver = if scope_versions.contains_key(&lhs) {
                    current_ver + 1
                } else {
                    0
                };
                scope_versions.insert(lhs.clone(), new_ver);

                let lhs_var = SsaVar::new(lhs.clone(), new_ver, current_scope.clone(), line_num).with_file(file_path);
                dfg.add_var(lhs_var.clone());

                // If assignment RHS is an untrusted HTTP source
                if is_http_source {
                    let src_kind = if trimmed.contains("$_GET") || trimmed.contains("req.query") || trimmed.contains("request.args") {
                        SourceKind::HttpQueryParam
                    } else if trimmed.contains("$_POST") || trimmed.contains("req.body") || trimmed.contains("request.form") {
                        SourceKind::HttpBodyParam
                    } else {
                        SourceKind::HttpHeader
                    };

                    let source = TaintSource::new(lhs_var.clone(), src_kind, "*")
                        .with_description(format!("Source assignment at {}:{}", file_path, line_num));
                    dfg.add_source(source);
                }

                // Check if RHS is a sanitizer call
                let mut is_sanitizer_edge = false;
                let mut matched_sanitizer = None;
                for rule in &dfg.sanitizers {
                    if rule.matches(&rhs, "*") || rhs.contains(&rule.name) {
                        is_sanitizer_edge = true;
                        matched_sanitizer = Some(rule.name.clone());
                        break;
                    }
                }

                // Extract variables used in RHS
                let rhs_vars = extract_vars_in_expr(&rhs, is_php, &scope_versions);

                for used_var_name in &rhs_vars {
                    if let Some(&used_ver) = scope_versions.get(used_var_name) {
                        let from_var = SsaVar::new(used_var_name.clone(), used_ver, current_scope.clone(), line_num)
                            .with_file(file_path);

                        let step_kind = if let Some(ref s_name) = matched_sanitizer {
                            TaintStepKind::SanitizerCall {
                                sanitizer_name: s_name.clone(),
                                cwe_targeted: "*".to_string(),
                            }
                        } else if rhs.contains('+') || rhs.contains('.') || rhs.contains(',') {
                            TaintStepKind::BinaryExpression
                        } else {
                            TaintStepKind::DirectAssignment
                        };

                        let edge = DataflowEdge {
                            from_var,
                            to_var: lhs_var.clone(),
                            step_kind,
                            line: line_num,
                            is_sanitizer: is_sanitizer_edge,
                            sanitizer_name: matched_sanitizer.clone(),
                            file_path: file_path.to_string(),
                            code_snippet: Some(trimmed.to_string()),
                        };
                        dfg.add_edge(edge);
                    }
                }

                // Check if RHS is an inter-procedural function call
                if let Some(call_cap) = re_call_expr().captures(&rhs) {
                    let callee = call_cap[1].split("::").last().unwrap_or(&call_cap[1]).split("->").last().unwrap_or(&call_cap[1]).trim().to_string();
                    let raw_args = &call_cap[2];
                    let mut arg_vars = Vec::new();
                    for a in extract_vars_in_expr(raw_args, is_php, &scope_versions) {
                        if let Some(&v) = scope_versions.get(&a) {
                            arg_vars.push(SsaVar::new(a, v, current_scope.clone(), line_num).with_file(file_path));
                        }
                    }

                    if !callee.is_empty() && callee != "query" && callee != "system" && callee != "exec" {
                        call_sites.push(CallSite {
                            caller: current_scope.clone(),
                            callee,
                            line: line_num,
                            arg_vars,
                            lhs_var: Some(lhs_var.clone()),
                        });
                    }
                }
            } else if let Some(call_cap) = re_call_expr().captures(trimmed) {
                // Statement function call without LHS assignment (e.g. `process($data);`)
                let callee = call_cap[1].split("::").last().unwrap_or(&call_cap[1]).split("->").last().unwrap_or(&call_cap[1]).trim().to_string();
                let raw_args = &call_cap[2];
                let mut arg_vars = Vec::new();
                for a in extract_vars_in_expr(raw_args, is_php, &scope_versions) {
                    if let Some(&v) = scope_versions.get(&a) {
                        arg_vars.push(SsaVar::new(a, v, current_scope.clone(), line_num).with_file(file_path));
                    }
                }

                if !callee.is_empty() && callee != "query" && callee != "system" && callee != "exec" {
                    call_sites.push(CallSite {
                        caller: current_scope.clone(),
                        callee,
                        line: line_num,
                        arg_vars,
                        lhs_var: None,
                    });
                }
            }

            // Detect Return statement
            if let Some(ret_cap) = re_return_stmt().captures(trimmed) {
                let ret_expr = ret_cap[1].trim();
                let ret_vars = extract_vars_in_expr(ret_expr, is_php, &scope_versions);
                if let Some(v_name) = ret_vars.first() {
                    if let Some(&v_ver) = scope_versions.get(v_name) {
                        let ret_var = SsaVar::new(v_name.clone(), v_ver, current_scope.clone(), line_num).with_file(file_path);
                        if let Some(f_meta) = functions.get_mut(&current_scope) {
                            f_meta.return_var = Some(ret_var);
                        }
                    }
                }
            }

            // Detect Sinks (CWE-89 SQLi, CWE-78 Command, CWE-79 XSS, CWE-22 Path)
            Self::detect_sinks_on_line(
                trimmed,
                line_num,
                file_path,
                &current_scope,
                &scope_versions,
                is_php,
                dfg,
            );
        }
    }

    /// Detects sink calls on a line and registers TaintSink records
    fn detect_sinks_on_line(
        trimmed: &str,
        line_num: usize,
        file_path: &str,
        scope: &str,
        scope_versions: &HashMap<String, usize>,
        is_php: bool,
        dfg: &mut DataflowGraph,
    ) {
        // 1. CWE-89 SQL Injection Sinks
        let is_sqli_sink = trimmed.contains("query(")
            || trimmed.contains("execute(")
            || trimmed.contains("mysqli_query(")
            || trimmed.contains("->query(")
            || trimmed.contains("->execute(")
            || trimmed.contains("raw_query(");

        if is_sqli_sink {
            let used_vars = extract_vars_in_expr(trimmed, is_php, scope_versions);
            for v in used_vars {
                if let Some(&ver) = scope_versions.get(&v) {
                    let var = SsaVar::new(v.clone(), ver, scope.to_string(), line_num).with_file(file_path);
                    let sink = TaintSink::new(var, SinkKind::SqlExecution, "CWE-89")
                        .with_rule("CWE-89-SQL-INJECTION", "CRITICAL")
                        .with_description(format!("SQL execution at {}:{}", file_path, line_num));
                    dfg.add_sink(sink);
                }
            }
        }

        // 2. CWE-78 Command Injection Sinks
        let is_cmd_sink = trimmed.contains("system(")
            || trimmed.contains("exec(")
            || trimmed.contains("shell_exec(")
            || trimmed.contains("passthru(")
            || trimmed.contains("popen(")
            || trimmed.contains("child_process.exec(")
            || trimmed.contains("Command::new(")
            || trimmed.contains("Process.Start(")
            || trimmed.contains("std.process.Child.run(");

        if is_cmd_sink && !trimmed.starts_with("function") {
            let used_vars = extract_vars_in_expr(trimmed, is_php, scope_versions);
            for v in used_vars {
                if let Some(&ver) = scope_versions.get(&v) {
                    let var = SsaVar::new(v.clone(), ver, scope.to_string(), line_num).with_file(file_path);
                    let sink = TaintSink::new(var, SinkKind::CommandExecution, "CWE-78")
                        .with_rule("CWE-78-COMMAND-INJECTION", "CRITICAL")
                        .with_description(format!("Command execution at {}:{}", file_path, line_num));
                    dfg.add_sink(sink);
                }
            }
        }

        // 3. CWE-79 XSS Sinks
        let is_xss_sink = trimmed.starts_with("echo ")
            || trimmed.starts_with("print ")
            || trimmed.contains("innerHTML =")
            || trimmed.contains("res.send(")
            || trimmed.contains("Response.Write(");

        if is_xss_sink {
            let used_vars = extract_vars_in_expr(trimmed, is_php, scope_versions);
            for v in used_vars {
                if let Some(&ver) = scope_versions.get(&v) {
                    let var = SsaVar::new(v.clone(), ver, scope.to_string(), line_num).with_file(file_path);
                    let sink = TaintSink::new(var, SinkKind::HtmlRender, "CWE-79")
                        .with_rule("CWE-79-XSS", "HIGH")
                        .with_description(format!("Unescaped HTML render at {}:{}", file_path, line_num));
                    dfg.add_sink(sink);
                }
            }
        }

        // 4. CWE-22 Path Traversal Sinks
        let is_path_sink = trimmed.contains("file_get_contents(")
            || trimmed.contains("readfile(")
            || (trimmed.contains("include ") && !trimmed.contains("class "))
            || (trimmed.contains("require ") && !trimmed.contains("class "))
            || trimmed.contains("fs.readFile(")
            || trimmed.contains("File.Open(")
            || trimmed.contains("File.ReadAllText(")
            || trimmed.contains("std.fs.cwd().openFile(")
            || trimmed.contains("open(");

        if is_path_sink {
            let used_vars = extract_vars_in_expr(trimmed, is_php, scope_versions);
            for v in used_vars {
                if let Some(&ver) = scope_versions.get(&v) {
                    let var = SsaVar::new(v.clone(), ver, scope.to_string(), line_num).with_file(file_path);
                    let sink = TaintSink::new(var, SinkKind::FileAccess, "CWE-22")
                        .with_rule("CWE-22-PATH-TRAVERSAL", "HIGH")
                        .with_description(format!("File access at {}:{}", file_path, line_num));
                    dfg.add_sink(sink);
                }
            }
        }
    }

    /// Links call sites across functions (Inter-procedural propagation)
    fn link_inter_procedural(
        dfg: &mut DataflowGraph,
        functions: &HashMap<String, FunctionMeta>,
        call_sites: &[CallSite],
    ) {
        for call in call_sites {
            if let Some(target_meta) = functions.get(&call.callee) {
                // Link Caller arguments -> Callee parameters
                for (arg_idx, arg_var) in call.arg_vars.iter().enumerate() {
                    if arg_idx < target_meta.params.len() {
                        let param_name = &target_meta.params[arg_idx];
                        let param_var = SsaVar::new(
                            param_name.clone(),
                            0, // Initial parameter version in callee
                            target_meta.name.clone(),
                            target_meta.line,
                        )
                        .with_file(&target_meta.file_path);

                        let edge = DataflowEdge {
                            from_var: arg_var.clone(),
                            to_var: param_var,
                            step_kind: TaintStepKind::CallArgumentPassing {
                                caller_function: call.caller.clone(),
                                callee_function: target_meta.name.clone(),
                                arg_index: arg_idx,
                                param_name: param_name.clone(),
                            },
                            line: call.line,
                            is_sanitizer: false,
                            sanitizer_name: None,
                            file_path: target_meta.file_path.clone(),
                            code_snippet: Some(format!(
                                "{}({}) -> param {}",
                                target_meta.name, arg_var.display_id(), param_name
                            )),
                        };
                        dfg.add_edge(edge);
                    }
                }

                // Link Callee return value -> Caller LHS variable
                if let Some(ref lhs_var) = call.lhs_var {
                    if let Some(ref ret_var) = target_meta.return_var {
                        let edge = DataflowEdge {
                            from_var: ret_var.clone(),
                            to_var: lhs_var.clone(),
                            step_kind: TaintStepKind::CallReturnPassing {
                                caller_function: call.caller.clone(),
                                callee_function: target_meta.name.clone(),
                            },
                            line: call.line,
                            is_sanitizer: false,
                            sanitizer_name: None,
                            file_path: target_meta.file_path.clone(),
                            code_snippet: Some(format!(
                                "return {} -> {}",
                                ret_var.display_id(),
                                lhs_var.display_id()
                            )),
                        };
                        dfg.add_edge(edge);
                    }
                }
            }
        }
    }
}

/// Extracts variable names referenced in an expression that match known variables
fn extract_vars_in_expr(
    expr: &str,
    is_php: bool,
    known_vars: &HashMap<String, usize>,
) -> Vec<String> {
    let mut vars = Vec::new();
    if is_php {
        for cap in re_php_var().captures_iter(expr) {
            let v = cap[1].to_string();
            if (known_vars.contains_key(&v) || v.starts_with('$')) && !vars.contains(&v) {
                vars.push(v);
            }
        }
    } else {
        for cap in re_ident().captures_iter(expr) {
            let v = cap[1].to_string();
            if known_vars.contains_key(&v) && !vars.contains(&v) {
                vars.push(v);
            }
        }
    }
    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zig_taint_parameter_extraction() {
        let zig_code = r#"
pub fn executeCommand(cmd: []const u8, timeout: u32) !void {
    std.process.Child.run(cmd);
}
"#;
        let dfg = TaintExtractor::extract_from_source("server/worker.zig", zig_code, &[]);
        assert!(dfg.nodes.values().any(|v| v.name == "cmd" && v.version == 0));
        assert!(dfg.nodes.values().any(|v| v.name == "timeout" && v.version == 0));
        assert!(dfg.sinks.iter().any(|s| s.sink_kind == SinkKind::CommandExecution));
    }

    #[test]
    fn test_csharp_taint_parameter_extraction() {
        let cs_code = r#"
public class ReportController {
    public void RunReport(string query, int maxRows) {
        Process.Start(query);
    }
}
"#;
        let dfg = TaintExtractor::extract_from_source("server/ReportController.cs", cs_code, &[]);
        assert!(dfg.nodes.values().any(|v| v.name == "query" && v.version == 0));
        assert!(dfg.nodes.values().any(|v| v.name == "maxRows" && v.version == 0));
        assert!(dfg.sinks.iter().any(|s| s.sink_kind == SinkKind::CommandExecution));
    }
}
