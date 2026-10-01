use crowsi_control_contracts::{CertificateActionV2, CertificateExecutionCommandV2};
use rusqlite::{ErrorCode, Transaction, params};

use crate::{AdministratorError, Result, certificate_reservation_write_v2::to_i64};

pub(crate) fn reserve(tx: &Transaction<'_>, command: &CertificateExecutionCommandV2) -> Result<()> {
    let deployment = &command.binding.deployment;
    let target = &command.binding.target;
    let key = params![
        deployment.security_domain,
        deployment.deployment_id,
        target.provider,
        target.target_resource_id,
        command.action.fence_scope()
    ];
    tx.execute(
        "INSERT OR IGNORE INTO certificate_v2_resource_fences
         VALUES (?, ?, ?, ?, ?, 0)",
        key,
    )?;
    let stored: i64 = tx.query_row(
        "SELECT fence FROM certificate_v2_resource_fences
          WHERE security_domain = ? AND deployment_id = ? AND provider = ?
            AND target_resource_id = ? AND fence_scope = ?",
        key,
        |row| row.get(0),
    )?;
    if u64::try_from(stored).ok() != Some(target.previous_fence) {
        return Err(AdministratorError::FenceConflict);
    }
    if read_only(command.action) {
        return Ok(());
    }
    let result = tx.execute(
        "INSERT INTO certificate_v2_fence_reservations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            command.pa_reservation_id,
            deployment.security_domain,
            deployment.deployment_id,
            target.provider,
            target.target_resource_id,
            command.action.fence_scope(),
            to_i64(target.previous_fence)?,
            to_i64(target.current_fence)?
        ],
    );
    match result {
        Ok(1) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(value, _))
            if value.code == ErrorCode::ConstraintViolation =>
        {
            Err(AdministratorError::FenceConflict)
        }
        Ok(_) => Err(AdministratorError::LedgerIntegrity),
        Err(error) => Err(AdministratorError::Storage(error)),
    }
}

pub(crate) fn promote(tx: &Transaction<'_>, command: &CertificateExecutionCommandV2) -> Result<()> {
    if read_only(command.action) {
        return Ok(());
    }
    let deployment = &command.binding.deployment;
    let target = &command.binding.target;
    let changed = tx.execute(
        "UPDATE certificate_v2_resource_fences SET fence = ?
          WHERE security_domain = ? AND deployment_id = ? AND provider = ?
            AND target_resource_id = ? AND fence_scope = ? AND fence = ?",
        params![
            to_i64(target.current_fence)?,
            deployment.security_domain,
            deployment.deployment_id,
            target.provider,
            target.target_resource_id,
            command.action.fence_scope(),
            to_i64(target.previous_fence)?
        ],
    )?;
    if changed != 1 || discard(tx, command)? != 1 {
        return Err(AdministratorError::FenceConflict);
    }
    Ok(())
}

pub(crate) fn discard(
    tx: &Transaction<'_>,
    command: &CertificateExecutionCommandV2,
) -> Result<usize> {
    if read_only(command.action) {
        return Ok(0);
    }
    Ok(tx.execute(
        "DELETE FROM certificate_v2_fence_reservations
          WHERE pa_reservation_id = ? AND previous_fence = ? AND proposed_fence = ?",
        params![
            command.pa_reservation_id,
            to_i64(command.binding.target.previous_fence)?,
            to_i64(command.binding.target.current_fence)?
        ],
    )?)
}

const fn read_only(action: CertificateActionV2) -> bool {
    matches!(
        action,
        CertificateActionV2::CertificateStatus | CertificateActionV2::OperationStatus
    )
}
