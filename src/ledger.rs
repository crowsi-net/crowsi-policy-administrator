use rusqlite::Connection;

use crate::{AdministratorError, Result, ledger_schema};

const APPLICATION_ID: i64 = 0x4352_5041;
const SCHEMA_VERSION: i64 = 7;

pub(crate) fn migrate(connection: &Connection) -> Result<()> {
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !matches!(application_id, 0 | APPLICATION_ID)
        || !matches!(version, 0 | 1 | 2 | 3 | 4 | 5 | 6 | SCHEMA_VERSION)
    {
        return Err(AdministratorError::LedgerIntegrity);
    }
    if version < 4 {
        connection.execute_batch(crate::ledger_ddl::SCHEMA)?;
    }
    if matches!(version, 5 | 6) {
        prepare_empty_certificate_upgrade(connection)?;
    }
    if version < SCHEMA_VERSION {
        connection.execute_batch(crate::certificate_ddl_v2::SCHEMA)?;
    }
    ledger_schema::verify(connection)
}

fn prepare_empty_certificate_upgrade(connection: &Connection) -> Result<()> {
    let state_tables = [
        "certificate_v2_reservations",
        "certificate_v2_approval_uses",
        "certificate_v2_authenticator_counters",
        "certificate_v2_signing_handoffs",
        "certificate_v2_lifecycle_epoch_reservations",
        "certificate_v2_fence_reservations",
        "certificate_v2_resource_fences",
        "certificate_v2_revocation_epochs",
        "certificate_v2_lifecycle_epochs",
        "certificate_v2_completion_evidence",
        "certificate_v2_completion_inbox",
        "certificate_v2_approval_authority_binding",
        "certificate_v2_outcome_authority_binding",
        "certificate_v2_manager_commit_binding",
        "certificate_v2_manager_handoff_binding",
        "certificate_v2_handoff_receipts",
        "certificate_v2_signer_binding",
        "certificate_v2_target_normalizer_binding",
        "certificate_v2_ledger_binding",
    ];
    if state_tables
        .into_iter()
        .any(|table| table_nonempty(connection, table).unwrap_or(true))
    {
        return Err(AdministratorError::LedgerIntegrity);
    }
    connection.execute_batch(
        "DROP TABLE IF EXISTS certificate_v2_approval_uses;
         DROP TABLE IF EXISTS certificate_v2_completion_evidence;
         DROP TABLE IF EXISTS certificate_v2_completion_inbox;
         DROP TABLE IF EXISTS certificate_v2_authenticator_counters;
         DROP TABLE IF EXISTS certificate_v2_signing_handoffs;
         DROP TABLE IF EXISTS certificate_v2_lifecycle_epoch_reservations;
         DROP TABLE IF EXISTS certificate_v2_fence_reservations;
         DROP TABLE IF EXISTS certificate_v2_approval_authority_binding;
         DROP TABLE IF EXISTS certificate_v2_outcome_authority_binding;
         DROP TABLE IF EXISTS certificate_v2_manager_commit_binding;
         DROP TABLE IF EXISTS certificate_v2_manager_handoff_binding;
         DROP TABLE IF EXISTS certificate_v2_handoff_receipts;
         DROP TABLE IF EXISTS certificate_v2_signer_binding;
         DROP TABLE IF EXISTS certificate_v2_target_normalizer_binding;
         DROP TABLE IF EXISTS certificate_v2_lifecycle_epochs;
         DROP TABLE IF EXISTS certificate_v2_revocation_epochs;
         DROP TABLE IF EXISTS certificate_v2_resource_fences;
         DROP TABLE IF EXISTS certificate_v2_ledger_binding;
         DROP TABLE IF EXISTS certificate_v2_reservations;",
    )?;
    Ok(())
}

fn table_nonempty(connection: &Connection, table: &str) -> Result<bool> {
    let exists: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = ?",
        [table],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Ok(false);
    }
    let sql = format!("SELECT EXISTS(SELECT 1 FROM {table} LIMIT 1)");
    Ok(connection.query_row(&sql, [], |row| row.get::<_, i64>(0))? == 1)
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod tests;
