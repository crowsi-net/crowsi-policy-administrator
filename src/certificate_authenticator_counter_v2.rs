use crowsi_control_contracts::CertificateApprovalEvidenceV2;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::{AdministratorError, Result, certificate_reservation_write_v2::to_i64};

pub(crate) fn observe(
    tx: &Transaction<'_>,
    evidence: &CertificateApprovalEvidenceV2,
) -> Result<()> {
    let stored = tx
        .query_row(
            "SELECT sign_count, backup_eligible, backup_state
               FROM certificate_v2_authenticator_counters
              WHERE issuer = ? AND relying_party_id = ? AND credential_id = ?",
            params![
                evidence.issuer,
                evidence.relying_party_id,
                evidence.credential_id
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((count, eligible, backup)) = stored else {
        tx.execute(
            "INSERT INTO certificate_v2_authenticator_counters VALUES (?, ?, ?, ?, ?, ?)",
            params![
                evidence.issuer,
                evidence.relying_party_id,
                evidence.credential_id,
                to_i64(evidence.authenticator_sign_count)?,
                evidence.authenticator_backup_eligible,
                evidence.authenticator_backup_state
            ],
        )?;
        return Ok(());
    };
    let count = u64::try_from(count).map_err(|_| AdministratorError::LedgerIntegrity)?;
    let counter_valid = (count == 0 && evidence.authenticator_sign_count == 0)
        || evidence.authenticator_sign_count > count;
    if !counter_valid
        || eligible != evidence.authenticator_backup_eligible
        || (backup && !evidence.authenticator_backup_state)
    {
        return Err(AdministratorError::Replay);
    }
    let changed = tx.execute(
        "UPDATE certificate_v2_authenticator_counters
            SET sign_count = ?, backup_state = ?
          WHERE issuer = ? AND relying_party_id = ? AND credential_id = ?
            AND sign_count = ? AND backup_eligible = ? AND backup_state = ?",
        params![
            to_i64(evidence.authenticator_sign_count)?,
            evidence.authenticator_backup_state,
            evidence.issuer,
            evidence.relying_party_id,
            evidence.credential_id,
            to_i64(count)?,
            eligible,
            backup
        ],
    )?;
    (changed == 1)
        .then_some(())
        .ok_or(AdministratorError::Replay)
}
