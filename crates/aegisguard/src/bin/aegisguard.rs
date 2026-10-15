use aegisguard::{audit, evaluate, EvaluateRequest};
use std::{env, fs};
fn main() {
    let mut a = env::args().skip(1); let cmd = a.next().unwrap_or_default();
    let result = match cmd.as_str() {
        "evaluate" => { let command = a.collect::<Vec<_>>().join(" "); let r = evaluate(&EvaluateRequest { command: command.clone(), cwd: None, actor: None }); let _ = audit::record("aegisguard.audit.jsonl", &command, &r); println!("{}", serde_json::to_string(&r).unwrap()); Ok(()) }
        "rollback" => { let from = a.next().ok_or("rollback requires snapshot and destination")?; let to = a.next().ok_or("rollback requires snapshot and destination")?; fs::copy(from, to).map(|_| ()) .map_err(|e| e.to_string()) }
        _ => Err("usage: aegisguard evaluate <command> | rollback <snapshot> <destination>".to_string()),
    }; if let Err(e) = result { eprintln!("error: {e}"); std::process::exit(2); }
}
