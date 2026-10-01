use crate::support;

use crowsi_control_contracts::ControlAction;
use crowsi_policy_administrator::AdministratorError;
use rusqlite::Connection;

use support::{Fixture, TestLedger};

#[test]
fn reserve_rejects_clock_rollback_after_ledger_reopen() {
    let ledger = TestLedger::new();
    let first = Fixture::version(1, 7, ControlAction::Quarantine).expect("first");
    {
        let mut administrator = first
            .administrator_on_path_at(ledger.path(), "2026-07-29T00:02:00.000Z")
            .expect("first administrator");
        administrator
            .reserve(&first.reservation(0, 1))
            .expect("first reservation");
    }
    let second = Fixture::version(2, 7, ControlAction::Quarantine).expect("second");
    let mut reopened = second
        .administrator_on_path_at(ledger.path(), "2026-07-29T00:01:59.999Z")
        .expect("reopened administrator");
    assert!(matches!(
        reopened.reserve(&second.reservation(1, 2)),
        Err(AdministratorError::ClockRollback)
    ));
}

#[test]
fn receipt_rejects_clock_rollback_after_ledger_reopen() {
    let ledger = TestLedger::new();
    let fixture = Fixture::new().expect("fixture");
    {
        let mut administrator = fixture
            .administrator_on_path_at(ledger.path(), "2026-07-29T00:02:00.000Z")
            .expect("first administrator");
        administrator
            .reserve(&fixture.reservation(0, 1))
            .expect("reservation");
    }
    let mut reopened = fixture
        .administrator_on_path_at(ledger.path(), "2026-07-29T00:01:59.999Z")
        .expect("reopened administrator");
    assert!(matches!(
        reopened.record_receipt(&fixture.receipt().expect("receipt")),
        Err(AdministratorError::ClockRollback)
    ));
}

#[test]
fn forward_clock_progress_remains_usable_after_reopen() {
    let ledger = TestLedger::new();
    let first = Fixture::version(1, 7, ControlAction::Quarantine).expect("first");
    {
        let mut administrator = first
            .administrator_on_path_at(ledger.path(), "2026-07-29T00:02:00.000Z")
            .expect("first administrator");
        administrator
            .reserve(&first.reservation(0, 1))
            .expect("first reservation");
    }
    let second = Fixture::version(2, 7, ControlAction::Quarantine).expect("second");
    let mut reopened = second
        .administrator_on_path_at(ledger.path(), "2026-07-29T00:02:01.000Z")
        .expect("reopened administrator");
    reopened
        .reserve(&second.reservation(1, 2))
        .expect("forward reservation");
}

#[test]
fn version_one_ledger_migrates_to_the_v2_command_schema() {
    let ledger = TestLedger::new();
    let connection = Connection::open(ledger.path()).expect("legacy ledger");
    connection
        .execute_batch(
            "PRAGMA application_id = 1129467969;
             PRAGMA user_version = 1;",
        )
        .expect("legacy version");
    drop(connection);
    let fixture = Fixture::new().expect("fixture");
    {
        let mut administrator = fixture
            .administrator_on_path_at(ledger.path(), "2026-07-29T00:02:00.000Z")
            .expect("migrated administrator");
        administrator
            .reserve(&fixture.reservation(0, 1))
            .expect("reservation");
    }
    let connection = Connection::open(ledger.path()).expect("migrated ledger");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("schema version");
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .expect("journal mode");
    let watermarks: i64 = connection
        .query_row("SELECT COUNT(*) FROM trusted_clock_watermark", [], |row| {
            row.get(0)
        })
        .expect("watermark count");
    assert_eq!(version, 7);
    assert_eq!(journal, "wal");
    assert_eq!(watermarks, 1);
}

#[test]
fn version_three_ledger_adds_signed_receipt_storage() {
    let ledger = TestLedger::new();
    let fixture = Fixture::new().expect("fixture");
    {
        fixture
            .administrator_on_path_at(ledger.path(), "2026-07-29T00:02:00.000Z")
            .expect("initialize");
    }
    let connection = Connection::open(ledger.path()).expect("legacy ledger");
    connection
        .execute_batch(
            "DROP TABLE v2_signed_receipts;
             PRAGMA user_version = 3;",
        )
        .expect("simulate v3");
    drop(connection);
    fixture
        .administrator_on_path_at(ledger.path(), "2026-07-29T00:02:00.000Z")
        .expect("migrate");
    let connection = Connection::open(ledger.path()).expect("migrated ledger");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("version");
    let tables: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
              WHERE type = 'table' AND name = 'v2_signed_receipts'",
            [],
            |row| row.get(0),
        )
        .expect("table");
    assert_eq!(version, 7);
    assert_eq!(tables, 1);
}
