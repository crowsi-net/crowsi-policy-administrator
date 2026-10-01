use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_LEDGER: AtomicU64 = AtomicU64::new(1);

pub struct TestLedger {
    path: PathBuf,
}

impl TestLedger {
    pub fn new() -> Self {
        let serial = NEXT_LEDGER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "crowsi-pa-test-{}-{serial}.sqlite3",
            std::process::id()
        ));
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestLedger {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut candidate = OsString::from(self.path.as_os_str());
            candidate.push(suffix);
            let _ = fs::remove_file(PathBuf::from(candidate));
        }
    }
}
