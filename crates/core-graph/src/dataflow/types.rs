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
#[derive(Clone, Debug, Serialize, PartialEq, Eq, Hash)]
pub enum SourceKind {
    HttpQueryParam,
    HttpBodyParam,
    HttpHeader,
    HttpCookie,
    WebSocketPayload,
    FileSystemRead,
    DatabaseRead,
    EnvironmentVar,
    FunctionArgument,
    Custom(String),
}

impl SourceKind {
    fn from_label(s: &str) -> Self {
        match s.trim() {
            "HttpQueryParam" | "http_query_param" => SourceKind::HttpQueryParam,
            "HttpBodyParam" | "http_body_param" => SourceKind::HttpBodyParam,
            "HttpHeader" | "http_header" => SourceKind::HttpHeader,
            "HttpCookie" | "http_cookie" => SourceKind::HttpCookie,
            "WebSocketPayload" | "websocket_payload" => SourceKind::WebSocketPayload,
            "FileSystemRead" | "file_system_read" => SourceKind::FileSystemRead,
            "DatabaseRead" | "database_read" => SourceKind::DatabaseRead,
            "EnvironmentVar" | "environment_var" | "env_var" => SourceKind::EnvironmentVar,
            "FunctionArgument" | "function_argument" => SourceKind::FunctionArgument,
            "Custom" => SourceKind::Custom("Custom".to_string()),
            "custom" => SourceKind::Custom("custom".to_string()),
            other => SourceKind::Custom(other.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for SourceKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SourceKindVisitor;

        impl<'de> serde::de::Visitor<'de> for SourceKindVisitor {
            type Value = SourceKind;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a SourceKind string, map, or YAML tagged enum")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SourceKind::from_label(v))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SourceKind::from_label(&v))
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                if let Some((k, v)) = map.next_entry::<String, String>()? {
                    if k.eq_ignore_ascii_case("custom") {
                        Ok(SourceKind::Custom(v))
                    } else {
                        Ok(SourceKind::Custom(format!("{k}:{v}")))
                    }
                } else {
                    Ok(SourceKind::default())
                }
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::EnumAccess<'de>,
            {
                use serde::de::VariantAccess;
                let (tag, variant) = data.variant::<String>()?;
                if tag.eq_ignore_ascii_case("custom") {
                    let val = variant.newtype_variant::<String>()?;
                    Ok(SourceKind::Custom(val))
                } else {
                    let _ = variant.unit_variant();
                    Ok(SourceKind::from_label(&tag))
                }
            }
        }

        deserializer.deserialize_any(SourceKindVisitor)
    }
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
            Self::DatabaseRead => "Database Read", Self::EnvironmentVar => "Environment Variable",
            Self::FunctionArgument => "Function Argument",
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
#[derive(Clone, Debug, Serialize, PartialEq, Eq, Hash)]
pub enum SinkKind {
    SqlExecution,
    CommandExecution,
    HtmlRender,
    FileAccess,
    SsrfNetworkRequest,
    Deserialization,
    CodeEval,
    LdapQuery,
    Custom(String),
}

impl SinkKind {
    fn from_label(s: &str) -> Self {
        match s.trim() {
            "SqlExecution" | "sql_execution" => SinkKind::SqlExecution,
            "CommandExecution" | "command_execution" => SinkKind::CommandExecution,
            "HtmlRender" | "html_render" => SinkKind::HtmlRender,
            "FileAccess" | "file_access" => SinkKind::FileAccess,
            "SsrfNetworkRequest" | "ssrf_network_request" => SinkKind::SsrfNetworkRequest,
            "Deserialization" | "deserialization" => SinkKind::Deserialization,
            "CodeEval" | "code_eval" => SinkKind::CodeEval,
            "LdapQuery" | "ldap_query" => SinkKind::LdapQuery,
            "Custom" => SinkKind::Custom("Custom".to_string()),
            "custom" => SinkKind::Custom("custom".to_string()),
            other => SinkKind::Custom(other.to_string()),
        }
    }
}

impl<'de> Deserialize<'de> for SinkKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SinkKindVisitor;

        impl<'de> serde::de::Visitor<'de> for SinkKindVisitor {
            type Value = SinkKind;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a SinkKind string, map, or YAML tagged enum")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SinkKind::from_label(v))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SinkKind::from_label(&v))
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                if let Some((k, v)) = map.next_entry::<String, String>()? {
                    if k.eq_ignore_ascii_case("custom") {
                        Ok(SinkKind::Custom(v))
                    } else {
                        Ok(SinkKind::Custom(format!("{k}:{v}")))
                    }
                } else {
                    Ok(SinkKind::default())
                }
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::EnumAccess<'de>,
            {
                use serde::de::VariantAccess;
                let (tag, variant) = data.variant::<String>()?;
                if tag.eq_ignore_ascii_case("custom") {
                    let val = variant.newtype_variant::<String>()?;
                    Ok(SinkKind::Custom(val))
                } else {
                    let _ = variant.unit_variant();
                    Ok(SinkKind::from_label(&tag))
                }
            }
        }

        deserializer.deserialize_any(SinkKindVisitor)
    }
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
            Self::SsrfNetworkRequest => "SSRF Network Request",
            Self::Deserialization => "Insecure Deserialization",
            Self::CodeEval => "Dynamic Code Evaluation",
            Self::LdapQuery => "LDAP Query",
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

pub use super::rules::*;
