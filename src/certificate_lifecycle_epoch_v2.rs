use crowsi_control_contracts::{CertificateActionV2, CertificateExecutionCommandV2};
use rusqlite::{ErrorCode, Transaction, params};

use crate::{AdministratorError, Result, certificate_reservation_write_v2::to_i64};

pub(crate) fn reserve(tx: &Transaction<'_>, command: &CertificateExecutionCommandV2) -> Result<()> {
    let deployment = &command.binding.deployment;
    let target = &command.binding.target;
    tx.execute(
        "INSERT OR IGNORE INTO certificate_v2_lifecycle_epochs VALUES (?, ?, ?, ?, 0)",
        params![
            deployment.security_domain,
            deployment.deployment_id,
            target.provider,
            target.target_resource_id
        ],
    )?;
    let stored: i64 = tx.query_row(
        "SELECT epoch FROM certificate_v2_lifecycle_epochs
          WHERE security_domain = ? AND deployment_id = ? AND provider = ?
            AND target_resource_id = ?",
        params![
            deployment.security_domain,
            deployment.deployment_id,
            target.provider,
            target.target_resource_id
        ],
        |row| row.get(0),
    )?;
    let expected = match command.action {
        CertificateActionV2::Issue
        | CertificateActionV2::Renew
        | CertificateActionV2::Revoke
        | CertificateActionV2::CertificateStatus => target.previous_lifecycle_revocation_epoch,
        CertificateActionV2::OperationStatus | CertificateActionV2::ReconcileUnknown => {
            target.lifecycle_revocation_epoch
        }
    };
    if u64::try_from(stored).ok() != Some(expected) {
        return Err(AdministratorError::EpochConflict);
    }
    if command.action != CertificateActionV2::Revoke {
        return Ok(());
    }
    insert_pending(tx, command)
}

fn insert_pending(tx: &Transaction<'_>, command: &CertificateExecutionCommandV2) -> Result<()> {
    let deployment = &command.binding.deployment;
    let target = &command.binding.target;
    let result = tx.execute(
        "INSERT INTO certificate_v2_lifecycle_epoch_reservations
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        params![
            command.pa_reservation_id,
            deployment.security_domain,
            deployment.deployment_id,
            target.provider,
            target.target_resource_id,
            to_i64(target.previous_lifecycle_revocation_epoch)?,
            to_i64(target.lifecycle_revocation_epoch)?
        ],
    );
    match result {
        Ok(1) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(value, _))
            if value.code == ErrorCode::ConstraintViolation =>
        {
            Err(AdministratorError::EpochConflict)
        }
        Ok(_) => Err(AdministratorError::LedgerIntegrity),
        Err(error) => Err(AdministratorError::Storage(error)),
    }
}

pub(crate) fn promote(tx: &Transaction<'_>, command: &CertificateExecutionCommandV2) -> Result<()> {
    if command.action != CertificateActionV2::Revoke {
        return Ok(());
    }
    let deployment = &command.binding.deployment;
    let target = &command.binding.target;
    let changed = tx.execute(
        "UPDATE certificate_v2_lifecycle_epochs SET epoch = ?
          WHERE security_domain = ? AND deployment_id = ? AND provider = ?
            AND target_resource_id = ? AND epoch = ?",
        params![
            to_i64(target.lifecycle_revocation_epoch)?,
            deployment.security_domain,
            deployment.deployment_id,
            target.provider,
            target.target_resource_id,
            to_i64(target.previous_lifecycle_revocation_epoch)?
        ],
    )?;
    if changed != 1 || discard(tx, command)? != 1 {
        return Err(AdministratorError::EpochConflict);
    }
    Ok(())
}

pub(crate) fn discard(
    tx: &Transaction<'_>,
    command: &CertificateExecutionCommandV2,
) -> Result<usize> {
    if command.action != CertificateActionV2::Revoke {
        return Ok(0);
    }
    Ok(tx.execute(
        "DELETE FROM certificate_v2_lifecycle_epoch_reservations
          WHERE pa_reservation_id = ? AND previous_epoch = ? AND proposed_epoch = ?",
        params![
            command.pa_reservation_id,
            to_i64(command.binding.target.previous_lifecycle_revocation_epoch)?,
            to_i64(command.binding.target.lifecycle_revocation_epoch)?
        ],
    )?)
}
