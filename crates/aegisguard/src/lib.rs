//! Core protocol and audit primitives shared by the CLI and daemon.
pub mod audit;
pub mod protocol;
pub mod snapshot;
pub mod policy;
pub mod ledger;

pub use protocol::{evaluate, Decision, EvaluateRequest, EvaluateResponse};
pub use policy::{analyze_command, detect_secrets, Finding, FindingKind, PolicyDecision, RiskReport};
