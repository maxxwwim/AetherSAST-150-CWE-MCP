use regex::Regex;
use std::sync::OnceLock;

macro_rules! static_regex {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new($pattern).expect("Invalid static regex"))
        }
    };
}

pub(super) fn re_call_ident() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\b([A-Za-z0-9_]+)\s*\("#).expect("Invalid static regex"))
}

pub(crate) mod cpp;
pub(crate) mod csharp;
pub(crate) mod java;
pub(crate) mod jsts;
pub(crate) mod luau;
pub(crate) mod markdown;
pub(crate) mod php;
pub(crate) mod python;
pub(crate) mod rust;
pub(crate) mod solidity;
pub(crate) mod zig;

pub(crate) use cpp::analyze_cpp;
pub(crate) use csharp::analyze_csharp;
pub(crate) use java::analyze_java;
pub(crate) use jsts::analyze_jsts;
pub(crate) use luau::analyze_luau;
pub(crate) use markdown::analyze_markdown;
pub(crate) use php::analyze_php;
pub(crate) use python::analyze_python;
pub(crate) use rust::analyze_rust;
pub(crate) use solidity::analyze_solidity;
pub(crate) use zig::analyze_zig;
