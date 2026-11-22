//! SSA Dataflow Analysis & Taint Tracking Subsystem
//!
//! Provides inter-procedural SSA taint propagation, source-sink reachability analysis,
//! and sanitizer-based vulnerability neutralization.

pub mod engine;
pub mod graph;
pub mod rules;
pub mod types;

pub use engine::*;
pub use graph::*;
pub use rules::*;
pub use types::*;
