use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::{AdministratorError, Result};

const PRIVATE_MODE: u32 = 0o600;
const PROCESS_STATUS: &str = "/proc/self/status";

pub(crate) fn open(path: &Path) -> Result<Connection> {
    let parent = secure_parent(path)?;
    if !path.exists() {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_MODE)
            .open(path)
            .map_err(|_| AdministratorError::LedgerIntegrity)?;
    }
    let before = secure_file(path, &parent)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
    let connection = Connection::open_with_flags(path, flags)?;
    let after = secure_file(path, &parent)?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err(AdministratorError::LedgerIntegrity);
    }
    Ok(connection)
}

fn secure_parent(path: &Path) -> Result<fs::Metadata> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(AdministratorError::LedgerIntegrity);
    }
    let parent = path.parent().ok_or(AdministratorError::LedgerIntegrity)?;
    let canonical = fs::canonicalize(parent).map_err(|_| AdministratorError::LedgerIntegrity)?;
    if canonical != parent {
        return Err(AdministratorError::LedgerIntegrity);
    }
    let metadata = fs::symlink_metadata(parent).map_err(|_| AdministratorError::LedgerIntegrity)?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != effective_uid()?
    {
        return Err(AdministratorError::LedgerIntegrity);
    }
    Ok(metadata)
}

fn secure_file(path: &Path, parent: &fs::Metadata) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|_| AdministratorError::LedgerIntegrity)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != parent.uid()
    {
        return Err(AdministratorError::LedgerIntegrity);
    }
    Ok(metadata)
}

fn effective_uid() -> Result<u32> {
    let status =
        fs::read_to_string(PROCESS_STATUS).map_err(|_| AdministratorError::LedgerIntegrity)?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|fields| fields.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or(AdministratorError::LedgerIntegrity)?;
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{effective_uid, open};

    fn root(mode: u32) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("crowsi-pa-{suffix}"));
        DirBuilder::new().mode(mode).create(&path).unwrap();
        path
    }

    #[test]
    fn production_ledger_requires_a_private_canonical_parent() {
        let private = root(0o700);
        assert_eq!(
            fs::metadata(&private).unwrap().uid(),
            effective_uid().unwrap()
        );
        let ledger = private.join("ledger.sqlite3");
        let connection = open(&ledger).expect("private ledger");
        drop(connection);
        assert_eq!(
            fs::metadata(&ledger).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(private).unwrap();

        let exposed = root(0o755);
        assert!(open(&exposed.join("ledger.sqlite3")).is_err());
        fs::remove_dir_all(exposed).unwrap();
    }
}
