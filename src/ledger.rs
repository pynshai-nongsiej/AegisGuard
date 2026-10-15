use std::{fs, io, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot { pub id: String, pub path: PathBuf, pub bytes: Vec<u8>, pub created_unix: u64 }

/// A local snapshot ledger. Snapshots are memory-backed by default and can be persisted
/// by callers to a workspace-owned directory; rollback uses atomic rename where possible.
#[derive(Debug, Default)]
pub struct SnapshotLedger { snapshots: Vec<Snapshot> }

impl SnapshotLedger {
    pub fn new() -> Self { Self::default() }
    pub fn capture<P: AsRef<Path>>(&mut self, path: P) -> io::Result<String> {
        let path = path.as_ref().to_path_buf(); let bytes = fs::read(&path)?;
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let id = format!("{}-{}", stamp, self.snapshots.len());
        self.snapshots.push(Snapshot { id: id.clone(), path, bytes, created_unix: stamp as u64 / 1_000_000_000 }); Ok(id)
    }
    pub fn snapshot(&self, id: &str) -> Option<&Snapshot> { self.snapshots.iter().find(|s| s.id == id) }
    pub fn list(&self) -> &[Snapshot] { &self.snapshots }
    pub fn rollback(&self, id: &str) -> io::Result<()> {
        let s = self.snapshot(id).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "snapshot not found"))?;
        let tmp = s.path.with_extension("aegisguard.tmp"); fs::write(&tmp, &s.bytes)?; fs::rename(tmp, &s.path)?; Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn capture_and_rollback() { let d = std::env::temp_dir().join(format!("aegis-{}", std::process::id())); fs::write(&d, b"before").unwrap(); let mut l = SnapshotLedger::new(); let id=l.capture(&d).unwrap(); fs::write(&d,b"after").unwrap(); l.rollback(&id).unwrap(); assert_eq!(fs::read(&d).unwrap(), b"before"); let _=fs::remove_file(d); }
}
