use rusqlite::Connection;

use super::{SCHEMA_VERSION, migrate};
use crate::AdministratorError;

#[test]
fn precreated_weakened_schema_is_rejected() {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE resource_epochs (
               resource TEXT PRIMARY KEY,
               isolation_epoch INTEGER
             ) STRICT;
             PRAGMA application_id = 1129467969;
             PRAGMA user_version = 2;",
        )
        .unwrap();
    assert!(matches!(
        migrate(&connection),
        Err(AdministratorError::LedgerIntegrity)
    ));
}

#[test]
fn fresh_reopen_and_previous_version_end_at_current_schema() {
    let connection = Connection::open_in_memory().unwrap();
    migrate(&connection).unwrap();
    migrate(&connection).unwrap();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, SCHEMA_VERSION);

    let previous = Connection::open_in_memory().unwrap();
    previous.execute_batch(crate::ledger_ddl::SCHEMA).unwrap();
    previous.pragma_update(None, "user_version", 5).unwrap();
    migrate(&previous).unwrap();
    let migrated: i64 = previous
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(migrated, SCHEMA_VERSION);
}

#[test]
fn v5_with_certificate_state_is_refused_for_explicit_recovery() {
    let connection = Connection::open_in_memory().unwrap();
    connection.execute_batch(crate::ledger_ddl::SCHEMA).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE certificate_v2_reservations (
               authorization_jti TEXT PRIMARY KEY
             ) STRICT;
             INSERT INTO certificate_v2_reservations VALUES ('legacy.reserved.0001');
             PRAGMA user_version = 5;",
        )
        .unwrap();
    assert!(matches!(
        migrate(&connection),
        Err(AdministratorError::LedgerIntegrity)
    ));
}

#[test]
fn foreign_key_off_orphan_handoff_cannot_be_dropped_during_upgrade() {
    let connection = Connection::open_in_memory().unwrap();
    connection.execute_batch(crate::ledger_ddl::SCHEMA).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             CREATE TABLE certificate_v2_signing_handoffs (
               authorization_jti TEXT PRIMARY KEY
             ) STRICT;
             INSERT INTO certificate_v2_signing_handoffs
               VALUES ('orphan.authorization.0001');
             PRAGMA user_version = 6;",
        )
        .unwrap();
    assert!(matches!(
        migrate(&connection),
        Err(AdministratorError::LedgerIntegrity)
    ));
}
