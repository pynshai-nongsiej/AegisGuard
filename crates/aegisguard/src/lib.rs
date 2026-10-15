//! Core protocol and audit primitives shared by the CLI and daemon.
pub mod audit;
pub mod protocol;
pub mod snapshot;

pub use protocol::{evaluate, Decision, EvaluateRequest, EvaluateResponse};
