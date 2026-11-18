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
    #[serde(alias = "http_query_param")]
    HttpQueryParam,
    #[serde(alias = "http_body_param")]
    HttpBodyParam,
    #[serde(alias = "http_header")]
    HttpHeader,
    #[serde(alias = "http_cookie")]
    HttpCookie,
    #[serde(alias = "websocket_payload")]
    WebSocketPayload,
    #[serde(alias = "file_system_read")]
    FileSystemRead,
    #[serde(alias = "database_read")]
    DatabaseRead,
    #[serde(alias = "function_argument")]
    FunctionArgument,
    #[serde(alias = "custom")]
    Custom(String),
}

impl Default for SourceKind {
    fn default() -> Self {
        Self::Custom("custom".to_string())
    }
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
    #[serde(alias = "sql_execution")]
    SqlExecution,
    #[serde(alias = "command_execution")]
    CommandExecution,
    #[serde(alias = "html_render")]
    HtmlRender,
    #[serde(alias = "file_access")]
    FileAccess,
    #[serde(alias = "ssrf_network_request")]
    SsrfNetworkRequest,
    #[serde(alias = "ldap_query")]
    LdapQuery,
    #[serde(alias = "custom")]
    Custom(String),
}

impl Default for SinkKind {
    fn default() -> Self {
        Self::Custom("custom".to_string())
    }
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
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SanitizerMatchKind {
    #[default]
    #[serde(alias = "exact_name")]
    ExactName,
    #[serde(alias = "method_call")]
    MethodCall,
    #[serde(alias = "type_cast")]
    TypeCast,
    #[serde(alias = "regex_pattern")]
    RegexPattern,
}

/// A rule specifying a sanitizer function / method that neutralizes taint for specific CWEs.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SanitizerRule {
    pub name: String,
    #[serde(default)]
    pub target_cwes: Vec<String>,
    #[serde(default)]
    pub match_kind: SanitizerMatchKind,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
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

    pub fn matches_language(&self, lang_or_path: &str) -> bool {
        language_matches(self.language.as_deref(), lang_or_path)
    }

    pub fn matches_for_path(&self, func_or_expr: &str, sink_cwe: &str, lang_or_path: &str) -> bool {
        self.matches_language(lang_or_path) && self.matches(func_or_expr, sink_cwe)
    }

    pub fn matches(&self, func_or_expr: &str, sink_cwe: &str) -> bool {
        let is_cwe_match = self.neutralizes_all
            || self
                .target_cwes
                .iter()
                .any(|cwe| cwe_matches(cwe, sink_cwe));
        if !is_cwe_match { return false; }
        let expr = func_or_expr.trim();
        let callee = expr.split('(').next().unwrap_or(expr).trim();
        match self.match_kind {
            SanitizerMatchKind::ExactName => {
                expr == self.name
                    || callee == self.name
                    || callee.ends_with(&format!("::{}", self.name))
                    || callee.ends_with(&format!(".{}", self.name))
                    || callee.ends_with(&format!("->{}", self.name))
            }
            SanitizerMatchKind::MethodCall | SanitizerMatchKind::TypeCast => {
                expr == self.name || expr.contains(&self.name)
            }
            SanitizerMatchKind::RegexPattern => {
                let pat = &self.name;
                if pat.starts_with('*') && pat.ends_with('*') && pat.len() >= 2 {
                    expr.contains(&pat[1..pat.len() - 1])
                } else if pat.starts_with('*') {
                    callee.ends_with(&pat[1..]) || expr.ends_with(&pat[1..])
                } else if pat.ends_with('*') {
                    callee.starts_with(&pat[..pat.len() - 1]) || expr.starts_with(&pat[..pat.len() - 1])
                } else {
                    callee == pat || expr == pat
                }
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
            r("FromSqlInterpolated", &["CWE-89"], MethodCall), r("Parameters.AddWithValue", &["CWE-89"], MethodCall),
            r("HtmlEncoder.Default.Encode", &["CWE-79"], MethodCall), r("WebUtility.HtmlEncode", &["CWE-79"], MethodCall), r("HttpUtility.HtmlEncode", &["CWE-79"], MethodCall),
            r("Path.GetFileName", &["CWE-22"], MethodCall), r("ArgumentList.Add", &["CWE-78"], MethodCall),
            r("dupeZ", &["CWE-170"], MethodCall), r("bytesAsValue", &["CWE-843"], MethodCall), r("bytesAsSlice", &["CWE-843"], MethodCall),
            SanitizerRule::new_all("sanitize", ExactName), SanitizerRule::new_all("clean", ExactName),
        ]
    }
}

fn default_sink_severity() -> String {
    "HIGH".to_string()
}

fn extract_lang_token(lang_or_path: &str) -> String {
    let trimmed = lang_or_path.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let base = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed);
    let token = if let Some((_, ext)) = base.rsplit_once('.') {
        ext
    } else {
        base
    };
    token.to_ascii_lowercase()
}

/// Normalizes a language identifier or file path extension into a canonical language name.
pub fn normalize_language(lang_or_path: &str) -> Option<&'static str> {
    let token = extract_lang_token(lang_or_path);
    match token.as_str() {
        "rs" | "rust" => Some("rust"),
        "py" | "python" | "pyw" => Some("python"),
        "js" | "javascript" | "jsx" | "mjs" | "cjs" => Some("javascript"),
        "ts" | "typescript" | "tsx" | "mts" | "cts" => Some("typescript"),
        "php" | "phtml" | "php3" | "php4" | "php5" | "php7" | "phps" => Some("php"),
        "zig" => Some("zig"),
        "cs" | "c#" | "csharp" => Some("csharp"),
        "sol" | "solidity" => Some("solidity"),
        "go" | "golang" => Some("go"),
        "rb" | "ruby" => Some("ruby"),
        "c" | "h" => Some("c"),
        "cpp" | "c++" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => Some("cpp"),
        "java" => Some("java"),
        "lua" | "luau" => Some("lua"),
        _ => None,
    }
}

/// Checks whether a rule's optional language filter matches a target language name or file path.
pub fn language_matches(rule_lang: Option<&str>, target_lang_or_path: &str) -> bool {
    let Some(raw_rule) = rule_lang else {
        return true;
    };
    let trimmed_rule = raw_rule.trim();
    if trimmed_rule.is_empty()
        || trimmed_rule == "*"
        || trimmed_rule.eq_ignore_ascii_case("all")
        || trimmed_rule.eq_ignore_ascii_case("any")
    {
        return true;
    }

    let target_token = extract_lang_token(target_lang_or_path);
    if target_token.is_empty() {
        return false;
    }

    match (
        normalize_language(trimmed_rule),
        normalize_language(target_lang_or_path),
    ) {
        (Some(a), Some(b)) => a == b,
        (None, None) => extract_lang_token(trimmed_rule) == target_token,
        _ => false,
    }
}

fn pattern_matches_line(pattern: &str, line: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    if !pattern.contains('*') {
        return line.contains(pattern);
    }
    let mut rest = line;
    let mut has_segment = false;
    for part in pattern.split('*') {
        if part.is_empty() {
            continue;
        }
        has_segment = true;
        if let Some(pos) = rest.find(part) {
            rest = &rest[pos + part.len()..];
        } else {
            return false;
        }
    }
    has_segment || !line.is_empty()
}

fn contains_cwe_bounded(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let h_bytes = haystack.as_bytes();
    let n_bytes = needle.as_bytes();
    let first_is_digit = n_bytes[0].is_ascii_digit();
    let last_is_digit = n_bytes[n_bytes.len() - 1].is_ascii_digit();

    let mut search_from = 0usize;
    while let Some(rel_pos) = haystack[search_from..].find(needle) {
        let pos = search_from + rel_pos;
        let end = pos + needle.len();
        let left_ok = if pos == 0 {
            true
        } else if first_is_digit {
            !h_bytes[pos - 1].is_ascii_digit()
        } else {
            !h_bytes[pos - 1].is_ascii_alphanumeric()
        };
        let right_ok = if end == haystack.len() {
            true
        } else if last_is_digit {
            !h_bytes[end].is_ascii_digit()
        } else {
            !h_bytes[end].is_ascii_alphanumeric()
        };
        if left_ok && right_ok {
            return true;
        }
        search_from = pos + 1;
    }
    false
}

pub fn cwe_matches(rule_cwe: &str, target_cwe: &str) -> bool {
    let r = rule_cwe.trim();
    let t = target_cwe.trim();
    if r.is_empty() || r == "*" || t.is_empty() || t == "*" {
        return true;
    }
    if r.eq_ignore_ascii_case(t) {
        return true;
    }
    let r_up = r.to_ascii_uppercase();
    let t_up = t.to_ascii_uppercase();
    contains_cwe_bounded(&r_up, &t_up) || contains_cwe_bounded(&t_up, &r_up)
}

/// Declarative taint source rule for plugin/DSL-driven SSA dataflow analysis.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TaintSourceRule {
    pub name: String,
    #[serde(default)]
    pub source_kind: SourceKind,
    #[serde(default)]
    pub cwe: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default)]
    pub description: String,
}

impl TaintSourceRule {
    pub fn new(
        name: impl Into<String>,
        source_kind: SourceKind,
        cwe: impl Into<String>,
        patterns: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            source_kind,
            cwe: cwe.into(),
            patterns,
            language: None,
            description: String::new(),
        }
    }

    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe = cwe.into();
        self
    }

    pub fn with_language(mut self, lang: impl Into<String>) -> Self {
        self.language = Some(lang.into());
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn matches_language(&self, lang_or_path: &str) -> bool {
        language_matches(self.language.as_deref(), lang_or_path)
    }

    pub fn matches_line(&self, line: &str) -> bool {
        self.patterns.iter().any(|p| pattern_matches_line(p, line))
    }

    pub fn matches(&self, line: &str, lang_or_path: &str) -> bool {
        self.matches_language(lang_or_path) && self.matches_line(line)
    }

    pub fn to_taint_source(&self, var: SsaVar) -> TaintSource {
        let cwe = if self.cwe.is_empty() { "*" } else { self.cwe.as_str() };
        let mut src = TaintSource::new(var, self.source_kind.clone(), cwe);
        if !self.description.is_empty() {
            src = src.with_description(&self.description);
        }
        src
    }
}

/// Declarative taint sink rule for plugin/DSL-driven SSA dataflow analysis.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TaintSinkRule {
    pub name: String,
    #[serde(default)]
    pub sink_kind: SinkKind,
    #[serde(default)]
    pub cwe: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default = "default_sink_severity")]
    pub severity: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default)]
    pub description: String,
}

impl Default for TaintSinkRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            sink_kind: SinkKind::default(),
            cwe: String::new(),
            rule_id: String::new(),
            severity: default_sink_severity(),
            patterns: Vec::new(),
            language: None,
            description: String::new(),
        }
    }
}

impl TaintSinkRule {
    pub fn new(
        name: impl Into<String>,
        sink_kind: SinkKind,
        cwe: impl Into<String>,
        patterns: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            sink_kind,
            cwe: cwe.into(),
            rule_id: String::new(),
            severity: default_sink_severity(),
            patterns,
            language: None,
            description: String::new(),
        }
    }

    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe = cwe.into();
        self
    }

    pub fn with_rule(mut self, rule_id: impl Into<String>, severity: impl Into<String>) -> Self {
        self.rule_id = rule_id.into();
        self.severity = severity.into();
        self
    }

    pub fn with_language(mut self, lang: impl Into<String>) -> Self {
        self.language = Some(lang.into());
        self
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn matches_language(&self, lang_or_path: &str) -> bool {
        language_matches(self.language.as_deref(), lang_or_path)
    }

    pub fn matches_line(&self, line: &str) -> bool {
        self.patterns.iter().any(|p| pattern_matches_line(p, line))
    }

    pub fn matches(&self, line: &str, lang_or_path: &str) -> bool {
        self.matches_language(lang_or_path) && self.matches_line(line)
    }

    pub fn to_taint_sink(&self, var: SsaVar) -> TaintSink {
        let cwe = if self.cwe.is_empty() { "*" } else { self.cwe.as_str() };
        let rule_id = if self.rule_id.is_empty() { self.name.as_str() } else { self.rule_id.as_str() };
        let severity = if self.severity.is_empty() { "HIGH" } else { self.severity.as_str() };
        let mut sink = TaintSink::new(var, self.sink_kind.clone(), cwe).with_rule(rule_id, severity);
        if !self.description.is_empty() {
            sink = sink.with_description(&self.description);
        }
        sink
    }
}

/// Collection of declarative taint source, sink, and sanitizer rules.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintRuleSet {
    #[serde(default)]
    pub sources: Vec<TaintSourceRule>,
    #[serde(default)]
    pub sinks: Vec<TaintSinkRule>,
    #[serde(default)]
    pub sanitizers: Vec<SanitizerRule>,
}

impl TaintRuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty() && self.sinks.is_empty() && self.sanitizers.is_empty()
    }

    pub fn add_source(&mut self, rule: TaintSourceRule) {
        if !self.sources.contains(&rule) {
            self.sources.push(rule);
        }
    }

    pub fn add_sink(&mut self, rule: TaintSinkRule) {
        if !self.sinks.contains(&rule) {
            self.sinks.push(rule);
        }
    }

    pub fn add_sanitizer(&mut self, rule: SanitizerRule) {
        if !self.sanitizers.contains(&rule) {
            self.sanitizers.push(rule);
        }
    }

    /// Order-preserving, deduplicated merge of another rule set into `self`.
    pub fn merge(&mut self, other: &TaintRuleSet) {
        for src in &other.sources {
            self.add_source(src.clone());
        }
        for sink in &other.sinks {
            self.add_sink(sink.clone());
        }
        for san in &other.sanitizers {
            self.add_sanitizer(san.clone());
        }
    }

    pub fn sources_for_language(&self, lang_or_path: &str) -> Vec<&TaintSourceRule> {
        self.sources.iter().filter(|r| r.matches_language(lang_or_path)).collect()
    }

    pub fn sinks_for_language(&self, lang_or_path: &str) -> Vec<&TaintSinkRule> {
        self.sinks.iter().filter(|r| r.matches_language(lang_or_path)).collect()
    }

    pub fn sanitizers_for_language(&self, lang_or_path: &str) -> Vec<&SanitizerRule> {
        self.sanitizers.iter().filter(|r| r.matches_language(lang_or_path)).collect()
    }

    pub fn match_sources(&self, line: &str, lang_or_path: &str) -> Vec<&TaintSourceRule> {
        self.sources.iter().filter(|r| r.matches(line, lang_or_path)).collect()
    }

    pub fn match_sinks(&self, line: &str, lang_or_path: &str) -> Vec<&TaintSinkRule> {
        self.sinks.iter().filter(|r| r.matches(line, lang_or_path)).collect()
    }

    pub fn match_sanitizers(&self, expr: &str, sink_cwe: &str, lang_or_path: &str) -> Vec<&SanitizerRule> {
        self.sanitizers
            .iter()
            .filter(|r| r.matches_for_path(expr, sink_cwe, lang_or_path))
            .collect()
    }

    pub fn sources_for_cwe(&self, cwe: &str) -> Vec<&TaintSourceRule> {
        self.sources.iter().filter(|r| cwe_matches(&r.cwe, cwe)).collect()
    }

    pub fn sinks_for_cwe(&self, cwe: &str) -> Vec<&TaintSinkRule> {
        self.sinks.iter().filter(|r| cwe_matches(&r.cwe, cwe)).collect()
    }

    pub fn find_source(&self, name: &str) -> Option<&TaintSourceRule> {
        self.sources.iter().find(|r| r.name == name)
    }

    pub fn find_sink(&self, rule_id_or_name: &str) -> Option<&TaintSinkRule> {
        self.sinks
            .iter()
            .find(|r| (!r.rule_id.is_empty() && r.rule_id == rule_id_or_name) || r.name == rule_id_or_name)
    }
}
