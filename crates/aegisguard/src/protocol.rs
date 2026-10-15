use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision { Allow, Review, Deny }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateRequest {
    pub command: String,
    #[serde(default)] pub cwd: Option<String>,
    #[serde(default)] pub actor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    pub decision: Decision,
    pub score: u8,
    pub reasons: Vec<String>,
}

pub fn evaluate(req: &EvaluateRequest) -> EvaluateResponse {
    let report = crate::policy::analyze_command(&req.command);
    let decision = match report.decision { crate::policy::PolicyDecision::Allow => Decision::Allow, crate::policy::PolicyDecision::Review => Decision::Review, crate::policy::PolicyDecision::Deny => Decision::Deny };
    EvaluateResponse { decision, score: report.score, reasons: report.findings.into_iter().map(|f| format!("{} ({})", f.description, f.evidence)).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn destructive_commands_are_denied() {
        let r = evaluate(&EvaluateRequest { command: "rm -rf /tmp/x".into(), cwd: None, actor: None });
        assert_eq!(r.decision, Decision::Deny);
    }
    #[test]
    fn ordinary_commands_are_allowed() {
        let r = evaluate(&EvaluateRequest { command: "cargo test".into(), cwd: None, actor: None });
        assert_eq!(r.decision, Decision::Allow);
    }
}
