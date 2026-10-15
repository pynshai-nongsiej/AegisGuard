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
    let command = req.command.to_ascii_lowercase();
    let mut score = 0u8;
    let mut reasons = Vec::new();
    for (need, points, reason) in [
        ("rm -rf", 100, "destructive recursive deletion"),
        ("mkfs", 100, "filesystem destruction"),
        ("dd if=", 90, "raw disk write"),
        ("curl ", 35, "network transfer"),
        ("wget ", 35, "network transfer"),
        ("aws_secret_access_key", 75, "cloud secret exposure"),
        ("github_token", 75, "access token exposure"),
        (".env", 45, "environment secret access"),
        ("base64 -d", 25, "obfuscated payload"),
    ] { if command.contains(need) { score = score.saturating_add(points); reasons.push(reason.to_string()); } }
    let decision = if score >= 70 { Decision::Deny } else if score >= 30 { Decision::Review } else { Decision::Allow };
    EvaluateResponse { decision, score, reasons }
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
