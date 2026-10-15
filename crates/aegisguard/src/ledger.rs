use std::{fs, io, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

#[derive(Debug, Clone)] pub struct Snapshot { pub id: String, pub path: PathBuf, pub bytes: Vec<u8> }
#[derive(Debug, Default)] pub struct SnapshotLedger { snapshots: Vec<Snapshot> }
impl SnapshotLedger {
    pub fn new() -> Self { Self::default() }
    pub fn capture(&mut self, path: impl AsRef<Path>) -> io::Result<String> { let path = path.as_ref().to_path_buf(); let bytes = fs::read(&path)?; let id = format!("{}-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(), self.snapshots.len()); self.snapshots.push(Snapshot { id: id.clone(), path, bytes }); Ok(id) }
    pub fn rollback(&self, id: &str) -> io::Result<()> { let s = self.snapshots.iter().find(|s| s.id == id).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "snapshot not found"))?; let tmp = s.path.with_extension("aegisguard.tmp"); fs::write(&tmp, &s.bytes)?; fs::rename(tmp, &s.path) }
}
#[cfg(test)] mod tests { use super::*; #[test] fn restores_file() { let p = std::env::temp_dir().join(format!("aegisguard-{}", std::process::id())); fs::write(&p, b"before").unwrap(); let mut l = SnapshotLedger::new(); let id = l.capture(&p).unwrap(); fs::write(&p, b"after").unwrap(); l.rollback(&id).unwrap(); assert_eq!(fs::read(&p).unwrap(), b"before"); let _ = fs::remove_file(p); } }
