use serde::{Deserialize, Serialize};

/// Static Single Assignment (SSA) variable representation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SsaVar {
    pub name: String, pub version: usize, pub func_scope: String, pub line: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
}

impl SsaVar {
    pub fn new(name: impl Into<String>, version: usize, func_scope: impl Into<String>, line: usize) -> Self {
        Self { name: name.into(), version, func_scope: func_scope.into(), line, file_path: None }
    }
    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file_path = Some(file.into());
        self
    }
    pub fn display_id(&self) -> String { format!("{}#{}", self.name, self.version) }
    pub fn scoped_id(&self) -> String {
        if self.func_scope.is_empty() { self.display_id() } else { format!("{}::{}#{}", self.func_scope, self.name, self.version) }
    }
}

/// Category/Kind of untrusted input source.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SourceKind {
    HttpQueryParam, HttpBodyParam, HttpHeader, HttpCookie,
    WebSocketPayload, FileSystemRead, DatabaseRead, FunctionArgument, Custom(String),
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::HttpQueryParam => "HTTP Query Parameter", Self::HttpBodyParam => "HTTP Body Parameter",
            Self::HttpHeader => "HTTP Header", Self::HttpCookie => "HTTP Cookie",
            Self::WebSocketPayload => "WebSocket Payload", Self::FileSystemRead => "File System Read",
            Self::DatabaseRead => "Database Read", Self::FunctionArgument => "Function Argument",
            Self::Custom(s) => return write!(f, "Custom ({s})"),
        };
        write!(f, "{s}")
    }
}

/// Declares an origin of tainted/untrusted data.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TaintSource {
    pub var: SsaVar,
    pub source_kind: SourceKind,
    pub cwe: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub line: usize,
    #[serde(default)]
    pub description: String,
}

impl TaintSource {
    pub fn new(var: SsaVar, source_kind: SourceKind, cwe: impl Into<String>) -> Self {
        let (line, file_path) = (var.line, var.file_path.clone().unwrap_or_default());
        Self { var, source_kind, cwe: cwe.into(), file_path, line, description: String::new() }
    }
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// Category/Kind of critical security sink.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SinkKind {
    SqlExecution, CommandExecution, HtmlRender, FileAccess,
    SsrfNetworkRequest, LdapQuery, Custom(String),
}

impl std::fmt::Display for SinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::SqlExecution => "SQL Execution", Self::CommandExecution => "Command Execution",
            Self::HtmlRender => "HTML Render (XSS)", Self::FileAccess => "File Access (Path Traversal)",
            Self::SsrfNetworkRequest => "SSRF Network Request", Self::LdapQuery => "LDAP Query",
            Self::Custom(s) => return write!(f, "Custom ({s})"),
        };
        write!(f, "{s}")
    }
}

/// Declares a critical destination operation where tainted data can cause an exploit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TaintSink {
    pub var: SsaVar,
    pub sink_kind: SinkKind,
    pub cwe: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub line: usize,
    #[serde(default)]
    pub description: String,
}

impl TaintSink {
    pub fn new(var: SsaVar, sink_kind: SinkKind, cwe: impl Into<String>) -> Self {
        let line = var.line;
        let file_path = var.file_path.clone().unwrap_or_default();
        Self {
            var, sink_kind, cwe: cwe.into(), rule_id: String::new(),
            severity: "HIGH".to_string(), file_path, line, description: String::new(),
        }
    }
    pub fn with_rule(mut self, rule_id: impl Into<String>, severity: impl Into<String>) -> Self {
        self.rule_id = rule_id.into();
        self.severity = severity.into();
        self
    }
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// Step kind within a taint propagation path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TaintStepKind {
    DirectAssignment,
    BinaryExpression,
    CallArgumentPassing { caller_function: String, callee_function: String, arg_index: usize, param_name: String },
    CallReturnPassing { caller_function: String, callee_function: String },
    SanitizerCall { sanitizer_name: String, cwe_targeted: String },
    PhiJoin,
    Custom(String),
}

/// An elementary step in variable taint propagation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintStep {
    pub step_index: usize,
    pub from_var: SsaVar,
    pub to_var: SsaVar,
    pub step_kind: TaintStepKind,
    pub line: usize,
    pub is_sanitizer: bool,
    pub sanitizer_name: Option<String>,
    #[serde(default)]
    pub file_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_snippet: Option<String>,
}

impl TaintStep {
    pub fn new(
        step_index: usize, from_var: SsaVar, to_var: SsaVar, step_kind: TaintStepKind,
        line: usize, is_sanitizer: bool, sanitizer_name: Option<String>,
    ) -> Self {
        let file_path = to_var.file_path.clone().unwrap_or_default();
        Self { step_index, from_var, to_var, step_kind, line, is_sanitizer, sanitizer_name, file_path, code_snippet: None }
    }

    pub fn format_step(&self) -> String {
        let (from, to, l, idx) = (self.from_var.display_id(), self.to_var.display_id(), self.line, self.step_index);
        match &self.step_kind {
            TaintStepKind::DirectAssignment => format!("[Step {idx}] Direct Assignment: {from} -> {to} (L{l})"),
            TaintStepKind::BinaryExpression => format!("[Step {idx}] Binary Expression: {from} -> {to} (L{l})"),
            TaintStepKind::CallArgumentPassing { caller_function, callee_function, arg_index, param_name } =>
                format!("[Step {idx}] Inter-procedural Call: {caller_function}::{from} -> {callee_function}::{to} (arg {arg_index}, param '{param_name}', L{l})"),
            TaintStepKind::CallReturnPassing { caller_function, callee_function } =>
                format!("[Step {idx}] Call Return: {callee_function}::{from} -> {caller_function}::{to} (L{l})"),
            TaintStepKind::SanitizerCall { sanitizer_name, cwe_targeted } =>
                format!("[Step {idx}] Sanitizer Applied: {sanitizer_name}({from}) -> {to} [neutralizes {cwe_targeted}] (L{l})"),
            TaintStepKind::PhiJoin => format!("[Step {idx}] Phi Join: {from} -> {to} (L{l})"),
            TaintStepKind::Custom(c) => format!("[Step {idx}] {c}: {from} -> {to} (L{l})"),
        }
    }
}

/// Complete trace of a dataflow propagation path from Source to Sink.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintFlowTrace {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub steps: Vec<TaintStep>,
    pub is_sanitized: bool,
    #[serde(default)]
    pub applied_sanitizers: Vec<String>,
    #[serde(default)]
    pub is_vulnerable: bool,
}

impl TaintFlowTrace {
    pub fn new(source: TaintSource, sink: TaintSink, steps: Vec<TaintStep>, is_sanitized: bool, applied_sanitizers: Vec<String>) -> Self {
        Self { source, sink, steps, is_sanitized, applied_sanitizers, is_vulnerable: !is_sanitized }
    }

    pub fn format_trace(&self) -> String {
        let status = if self.is_sanitized { "SANITIZED (Neutralized - Safe)" } else { "VULNERABLE (Exploitable)" };
        let mut out = format!("Trace Source [{}] ({}) L{} -> Sink [{}] ({}) L{}\nStatus: {status}\n",
            self.source.var.display_id(), self.source.source_kind, self.source.line,
            self.sink.var.display_id(), self.sink.sink_kind, self.sink.line);
        if !self.applied_sanitizers.is_empty() { out.push_str(&format!("Applied Sanitizers: {}\n", self.applied_sanitizers.join(", "))); }
        out.push_str("Propagation Steps:\n");
        for step in &self.steps { out.push_str(&format!("  {}\n", step.format_step())); }
        out
    }

    pub fn traversed_variables(&self) -> Vec<String> {
        let mut vars = vec![self.source.var.display_id()];
        vars.extend(self.steps.iter().map(|s| s.to_var.display_id()));
        vars
    }

    pub fn traversed_scoped_variables(&self) -> Vec<String> {
        let mut vars = vec![self.source.var.scoped_id()];
        vars.extend(self.steps.iter().map(|s| s.to_var.scoped_id()));
        vars
    }
}

/// Match kind for sanitizer definitions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SanitizerMatchKind {
    ExactName,
    MethodCall,
    TypeCast,
    RegexPattern,
}

/// A rule specifying a sanitizer function / method that neutralizes taint for specific CWEs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizerRule {
    pub name: String,
    pub target_cwes: Vec<String>,
    pub match_kind: SanitizerMatchKind,
    pub language: Option<String>,
    pub neutralizes_all: bool,
}

impl SanitizerRule {
    pub fn new(name: impl Into<String>, target_cwes: Vec<String>, match_kind: SanitizerMatchKind) -> Self {
        Self { name: name.into(), target_cwes, match_kind, language: None, neutralizes_all: false }
    }

    pub fn new_all(name: impl Into<String>, match_kind: SanitizerMatchKind) -> Self {
        Self { name: name.into(), target_cwes: vec!["*".to_string()], match_kind, language: None, neutralizes_all: true }
    }

    pub fn with_language(mut self, lang: impl Into<String>) -> Self {
        self.language = Some(lang.into());
        self
    }

    pub fn matches(&self, func_or_expr: &str, sink_cwe: &str) -> bool {
        let cwe_matches = self.neutralizes_all
            || self.target_cwes.iter().any(|cwe| {
                cwe == "*" || sink_cwe == "*" || cwe.eq_ignore_ascii_case(sink_cwe)
                    || sink_cwe.contains(cwe.as_str()) || cwe.contains(sink_cwe)
            });
        if !cwe_matches { return false; }
        let expr = func_or_expr.trim();
        match self.match_kind {
            SanitizerMatchKind::ExactName => expr == self.name || expr.ends_with(&format!("::{}", self.name))
                || expr.ends_with(&format!(".{}", self.name)) || expr.ends_with(&format!("->{}", self.name)),
            SanitizerMatchKind::MethodCall | SanitizerMatchKind::TypeCast => expr == self.name || expr.contains(&self.name),
            SanitizerMatchKind::RegexPattern => {
                let pat = &self.name;
                if pat.starts_with('*') && pat.ends_with('*') && pat.len() >= 2 { expr.contains(&pat[1..pat.len() - 1]) }
                else if pat.starts_with('*') { expr.ends_with(&pat[1..]) }
                else if pat.ends_with('*') { expr.starts_with(&pat[..pat.len() - 1]) }
                else { expr == pat }
            }
        }
    }

    pub fn default_catalog() -> Vec<SanitizerRule> {
        let r = |n: &str, cwes: &[&str], k: SanitizerMatchKind| SanitizerRule::new(n, cwes.iter().map(|s| s.to_string()).collect(), k);
        use SanitizerMatchKind::*;
        vec![
            r("intval", &["CWE-89"], ExactName), r("floatval", &["CWE-89"], ExactName), r("(int)", &["CWE-89"], TypeCast), r("(float)", &["CWE-89"], TypeCast),
            r("clean_sql", &["CWE-89"], ExactName), r("prepare", &["CWE-89"], MethodCall), r("pdo_prepare", &["CWE-89"], ExactName), r("mysqli_real_escape_string", &["CWE-89"], ExactName),
            r("addslashes", &["CWE-89"], ExactName), r("bind_param", &["CWE-89"], MethodCall), r("bindValue", &["CWE-89"], MethodCall), r("PDO::quote", &["CWE-89"], MethodCall),
            r("mysql.escape", &["CWE-89"], MethodCall), r("sqlstring.escape", &["CWE-89"], MethodCall), r("escapeId", &["CWE-89"], ExactName), r("parseInt", &["CWE-89"], ExactName),
            r("Number", &["CWE-89"], ExactName), r("psycopg2.sql.Identifier", &["CWE-89"], MethodCall), r("psycopg2.sql.Literal", &["CWE-89"], MethodCall), r("sqlx::query!", &["CWE-89"], MethodCall),
            r("escapeshellarg", &["CWE-78"], ExactName), r("escapeshellcmd", &["CWE-78"], ExactName), r("shlex.quote", &["CWE-78"], MethodCall), r("shell-escape", &["CWE-78"], ExactName),
            r("execFile", &["CWE-78"], ExactName), r("htmlspecialchars", &["CWE-79"], ExactName), r("htmlentities", &["CWE-79"], ExactName), r("strip_tags", &["CWE-79"], ExactName),
            r("DOMPurify.sanitize", &["CWE-79"], MethodCall), r("sanitize_input", &["CWE-79", "CWE-89"], ExactName), r("sanitizeHtml", &["CWE-79"], ExactName),
            r("escape_html", &["CWE-79"], ExactName), r("escapeHtml", &["CWE-79"], ExactName), r("encodeURIComponent", &["CWE-79"], ExactName),
            r("validator.escape", &["CWE-79"], MethodCall), r("html.escape", &["CWE-79"], MethodCall), r("bleach.clean", &["CWE-79"], MethodCall), r("markupsafe.escape", &["CWE-79"], MethodCall),
            r("basename", &["CWE-22"], ExactName), r("sanitize_path", &["CWE-22"], ExactName), r("realpath", &["CWE-22"], ExactName), r("Path::canonicalize", &["CWE-22"], MethodCall),
            r("path.basename", &["CWE-22"], MethodCall), r("os.path.basename", &["CWE-22"], MethodCall),
            SanitizerRule::new_all("sanitize", ExactName), SanitizerRule::new_all("clean", ExactName),
        ]
    }
}
