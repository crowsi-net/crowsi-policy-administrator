use rusqlite::Connection;

use crate::{AdministratorError, Result};

pub(super) const EXPECTED: [(&str, &str); 5] = [
    (
        "enforcement_reservations",
        "CREATE TABLE enforcement_reservations (
          command_jti TEXT PRIMARY KEY, grant_jti TEXT NOT NULL UNIQUE,
          recovery_jti TEXT UNIQUE, resource TEXT NOT NULL, audience TEXT NOT NULL,
          action TEXT NOT NULL, purpose TEXT NOT NULL, channel TEXT NOT NULL,
          command_digest TEXT NOT NULL, policy_snapshot_id TEXT NOT NULL,
          policy_snapshot_digest TEXT NOT NULL,
          isolation_epoch INTEGER NOT NULL CHECK(isolation_epoch > 0),
          reserved_at TEXT NOT NULL, command_issued_at TEXT NOT NULL,
          command_expires_at TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN (
            'reserved', 'applied', 'rejected', 'failed', 'partial'
          )), outcome TEXT, receipt_id TEXT UNIQUE, receipt_digest TEXT
        ) STRICT",
    ),
    (
        "one_receipt_per_command",
        "CREATE UNIQUE INDEX one_receipt_per_command
         ON enforcement_reservations(command_jti)
         WHERE receipt_digest IS NOT NULL",
    ),
    (
        "resource_epochs",
        "CREATE TABLE resource_epochs (
          resource TEXT PRIMARY KEY,
          isolation_epoch INTEGER NOT NULL CHECK(isolation_epoch >= 0)
        ) STRICT",
    ),
    (
        "subject_revocation_epochs",
        "CREATE TABLE subject_revocation_epochs (
          issuer TEXT NOT NULL, pairwise_subject TEXT NOT NULL,
          revocation_epoch INTEGER NOT NULL CHECK(revocation_epoch >= 0),
          PRIMARY KEY(issuer, pairwise_subject)
        ) STRICT",
    ),
    (
        "trusted_clock_watermark",
        "CREATE TABLE trusted_clock_watermark (
          singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
          observed_at TEXT NOT NULL
        ) STRICT",
    ),
];

pub(crate) fn verify(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT name, sql FROM sqlite_schema
         WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let actual = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    let mut expected = EXPECTED
        .into_iter()
        .chain(crate::ledger_schema_v2::EXPECTED)
        .chain(crate::certificate_schema_v2::EXPECTED)
        .chain(crate::certificate_schema_security_v2::EXPECTED)
        .chain(crate::certificate_schema_completion_v2::EXPECTED)
        .collect::<Vec<_>>();
    expected.sort_unstable_by_key(|entry| entry.0);
    if actual.len() != expected.len() {
        return Err(AdministratorError::LedgerIntegrity);
    }
    for ((actual_name, actual_sql), (expected_name, expected_sql)) in actual.iter().zip(expected) {
        if actual_name != expected_name || normalized(actual_sql) != normalized(expected_sql) {
            return Err(AdministratorError::LedgerIntegrity);
        }
    }
    Ok(())
}

fn normalized(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}
