use std::{fs, io, path::{Path, PathBuf}};
/// Minimal snapshot ledger used by rollback. Snapshots are private sibling files.
pub fn snapshot(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let p = path.as_ref(); let out = p.with_extension("aegisguard.snapshot"); fs::copy(p, &out)?; Ok(out)
}
pub fn rollback(snapshot: impl AsRef<Path>, destination: impl AsRef<Path>) -> io::Result<()> {
    fs::copy(snapshot, destination)?; Ok(())
}
