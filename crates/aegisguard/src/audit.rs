use std::{fs::OpenOptions, io::{self, Write}, path::Path};
use crate::protocol::EvaluateResponse;

/// Append-only, SQLite-compatible audit boundary. A JSONL fallback keeps the core portable;
/// deployments may replace this sink with SQLite without changing the protocol.
pub fn record(path: impl AsRef<Path>, command: &str, response: &EvaluateResponse) -> io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let line = format!("{{\"command\":\"{}\",\"response\":{},\"timestamp\":{}}}\n", command.replace('\\', "\\\\").replace('"', "\\\""), response.to_json(), now);
    f.write_all(line.as_bytes())
}
