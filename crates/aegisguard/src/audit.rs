use std::{fs::OpenOptions, io::{self, Write}, path::Path};
use serde::Serialize;
use crate::protocol::EvaluateResponse;

/// Append-only, SQLite-compatible audit boundary. A JSONL fallback keeps the core portable;
/// deployments may replace this sink with SQLite without changing the protocol.
#[derive(Serialize)] struct Entry<'a> { command: &'a str, response: &'a EvaluateResponse, timestamp: u64 }
pub fn record(path: impl AsRef<Path>, command: &str, response: &EvaluateResponse) -> io::Result<()> {
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    serde_json::to_writer(&mut f, &Entry { command, response, timestamp: now }).map_err(io::Error::other)?;
    f.write_all(b"\n")
}
