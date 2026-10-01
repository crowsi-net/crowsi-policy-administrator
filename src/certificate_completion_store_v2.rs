use crowsi_control_contracts::{CertificateExecutionDispositionV2, CertificatePayloadV2};
use rusqlite::{Transaction, params};

use crate::{
    AdministratorError, CertificateCompletionInputV2, Result,
    certificate_completion_load_v2::CompletionReservation,
};

pub(crate) fn apply(
    tx: &Transaction<'_>,
    reservation: &CompletionReservation,
    input: &CertificateCompletionInputV2<'_>,
    recorded_at_epoch_s: u64,
) -> Result<()> {
    let authority = input.authority_evidence;
    let manager = input.manager_commit_evidence;
    let authority_json =
        serde_json::to_string(authority).map_err(|_| AdministratorError::LedgerIntegrity)?;
    let manager_json =
        serde_json::to_string(manager).map_err(|_| AdministratorError::LedgerIntegrity)?;
    tx.execute(
        "INSERT INTO certificate_v2_completion_evidence(
           commit_id, authority_evidence_id, authority_nonce_base64, manager_nonce_base64,
           authorization_jti, authority_evidence_digest_sha256,
           manager_commit_digest_sha256, authority_evidence_json, manager_commit_json,
           disposition, recorded_at_epoch_s
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            manager.commit_id,
            authority.evidence_id,
            authority.nonce_base64,
            manager.nonce_base64,
            authority.authorization_jti,
            authority.certificate_digest_sha256(),
            manager.certificate_digest_sha256(),
            authority_json,
            manager_json,
            authority.disposition.as_str(),
            i64::try_from(recorded_at_epoch_s).map_err(|_| AdministratorError::Time)?
        ],
    )
    .map_err(|error| {
        if matches!(
            error,
            rusqlite::Error::SqliteFailure(failure, _)
                if failure.code == rusqlite::ErrorCode::ConstraintViolation
        ) {
            AdministratorError::Replay
        } else {
            AdministratorError::Storage(error)
        }
    })?;
    if authority.disposition == CertificateExecutionDispositionV2::StillUnknown {
        consume_current(tx, authority)
    } else {
        resolve(tx, reservation, authority)
    }
}

fn consume_current(
    tx: &Transaction<'_>,
    evidence: &crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
) -> Result<()> {
    let changed = tx.execute(
        "UPDATE certificate_v2_reservations SET state = 'consumed'
          WHERE authorization_jti = ? AND state = 'executing'
            AND lease_digest_sha256 = ?",
        params![evidence.authorization_jti, evidence.lease_digest_sha256],
    )?;
    (changed == 1)
        .then_some(())
        .ok_or(AdministratorError::Replay)
}

fn resolve(
    tx: &Transaction<'_>,
    reservation: &CompletionReservation,
    evidence: &crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
) -> Result<()> {
    let changed = tx.execute(
        "UPDATE certificate_v2_reservations SET state = 'consumed'
          WHERE authorization_jti = ? AND state = 'executing'
            AND lease_digest_sha256 = ?",
        params![evidence.authorization_jti, evidence.lease_digest_sha256],
    )?;
    if changed != 1 {
        return Err(AdministratorError::Replay);
    }
    if evidence.action == crowsi_control_contracts::CertificateActionV2::ReconcileUnknown {
        let related = reservation
            .related_authorization_jti
            .as_deref()
            .ok_or(AdministratorError::Binding)?;
        let resolved = tx.execute(
            "UPDATE certificate_v2_reservations SET state = 'reconciled'
              WHERE authorization_jti = ? AND state = 'result-unknown'",
            [related],
        )?;
        if resolved != 1 {
            return Err(AdministratorError::Binding);
        }
    }
    Ok(())
}
