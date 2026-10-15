//! Local, dependency-free policy primitives for AegisGuard.
//! The policy is intentionally fail-closed for credential exfiltration and destruction.

pub mod policy;
pub mod ledger;

pub use ledger::{Snapshot, SnapshotLedger};
pub use policy::{analyze_command, detect_secrets, Decision, Finding, FindingKind, RiskReport};
