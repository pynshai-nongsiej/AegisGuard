use crate::policy::{analyze_command, PolicyDecision};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision { Allow, Review, Deny }

#[derive(Debug, Clone)]
pub struct EvaluateRequest { pub command: String, pub cwd: Option<String>, pub actor: Option<String> }

#[derive(Debug, Clone)]
pub struct EvaluateResponse { pub decision: Decision, pub score: u8, pub reasons: Vec<String> }

impl EvaluateRequest {
    pub fn from_json_line(line: &str) -> Result<Self, String> {
        let command = json_string_field(line, "command").ok_or_else(|| "missing command".to_string())?;
        Ok(Self { command, cwd: json_string_field(line, "cwd"), actor: json_string_field(line, "actor") })
    }
}

impl EvaluateResponse {
    pub fn to_json(&self) -> String {
        let decision = match self.decision { Decision::Allow => "Allow", Decision::Review => "Review", Decision::Deny => "Deny" };
        let reasons = self.reasons.iter().map(|r| format!("\"{}\"", escape_json(r))).collect::<Vec<_>>().join(",");
        format!("{{\"decision\":\"{decision}\",\"score\":{},\"reasons\":[{}]}}", self.score, reasons)
    }
}

pub fn evaluate(req: &EvaluateRequest) -> EvaluateResponse {
    let report = analyze_command(&req.command);
    let decision = match report.decision { PolicyDecision::Allow => Decision::Allow, PolicyDecision::Review => Decision::Review, PolicyDecision::Deny => Decision::Deny };
    EvaluateResponse { decision, score: report.score, reasons: report.findings.into_iter().map(|f| format!("{} ({})", f.description, f.evidence)).collect() }
}

fn escape_json(value: &str) -> String { value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n") }

fn json_string_field(input: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\""); let start = input.find(&needle)?; let rest = &input[start + needle.len()..]; let colon = rest.find(':')?; let mut chars = rest[colon + 1..].trim_start().chars(); if chars.next()? != '"' { return None; }
    let mut value = String::new(); let mut escaped = false;
    for ch in chars { if escaped { value.push(match ch { 'n' => '\n', 'r' => '\r', 't' => '\t', other => other }); escaped = false; } else if ch == '\\' { escaped = true; } else if ch == '"' { return Some(value); } else { value.push(ch); } }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn parses_and_serializes() { let req = EvaluateRequest::from_json_line(r#"{"command":"git status"}"#).unwrap(); assert_eq!(evaluate(&req).decision, Decision::Allow); }
    #[test] fn destructive_commands_are_denied() { let r = evaluate(&EvaluateRequest { command: "rm -rf /tmp/x".into(), cwd: None, actor: None }); assert_eq!(r.decision, Decision::Deny); }
}
