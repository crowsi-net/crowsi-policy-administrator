use crowsi_control_contracts::{CertificatePayloadV2, Validate};
use rusqlite::{Transaction, params};

use crate::{
    AdministratorError, CertificateCompletionInputV2, CertificateCompletionReceiptV2, Result,
    certificate_completion_inbox_v2::CompletionInboxRecord,
};

pub(crate) fn insert_prepared(
    tx: &Transaction<'_>,
    input: &CertificateCompletionInputV2<'_>,
    received_at_epoch_s: u64,
    max_recovery_seconds: u64,
) -> Result<CompletionInboxRecord> {
    let maximum = input
        .manager_commit_evidence
        .committed_at_epoch_s
        .checked_add(max_recovery_seconds)
        .ok_or(AdministratorError::Time)?;
    let deadline = input
        .manager_commit_evidence
        .submission_recovery_deadline_epoch_s;
    if received_at_epoch_s > deadline || deadline > maximum {
        return Err(AdministratorError::Time);
    }
    let result = tx.execute(
        "INSERT INTO certificate_v2_completion_inbox(
           authorization_jti, commit_id, authority_evidence_id,
           authority_evidence_digest_sha256, manager_commit_digest_sha256,
           authority_evidence_json, manager_commit_json, disposition,
           received_at_epoch_s, recovery_deadline_epoch_s, state
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared')",
        params![
            input.authority_evidence.authorization_jti,
            input.manager_commit_evidence.commit_id,
            input.authority_evidence.evidence_id,
            input.authority_evidence.certificate_digest_sha256(),
            input.manager_commit_evidence.certificate_digest_sha256(),
            closed_json(input.authority_evidence)?,
            closed_json(input.manager_commit_evidence)?,
            input.authority_evidence.disposition.as_str(),
            to_i64(received_at_epoch_s)?,
            to_i64(deadline)?
        ],
    );
    if let Err(error) = result {
        return Err(if constraint(&error) {
            AdministratorError::Replay
        } else {
            AdministratorError::Storage(error)
        });
    }
    Ok(CompletionInboxRecord {
        received_at_epoch_s,
        recovery_deadline_epoch_s: deadline,
        state: "prepared".into(),
        completed_at_epoch_s: None,
    })
}

pub(crate) fn complete(
    tx: &Transaction<'_>,
    input: &CertificateCompletionInputV2<'_>,
    record: &CompletionInboxRecord,
    completed_at_epoch_s: u64,
) -> Result<CertificateCompletionReceiptV2> {
    let changed = tx.execute(
        "UPDATE certificate_v2_completion_inbox
            SET state = 'completed', completed_at_epoch_s = ?
          WHERE authorization_jti = ? AND state = 'prepared'
            AND completed_at_epoch_s IS NULL",
        params![
            to_i64(completed_at_epoch_s)?,
            input.authority_evidence.authorization_jti
        ],
    )?;
    if changed != 1 {
        return Err(AdministratorError::Replay);
    }
    Ok(receipt(
        input,
        record.received_at_epoch_s,
        completed_at_epoch_s,
    ))
}

pub(crate) fn completed_receipt(
    input: &CertificateCompletionInputV2<'_>,
    record: &CompletionInboxRecord,
) -> Result<CertificateCompletionReceiptV2> {
    if record.state != "completed" {
        return Err(AdministratorError::LedgerIntegrity);
    }
    Ok(receipt(
        input,
        record.received_at_epoch_s,
        record
            .completed_at_epoch_s
            .ok_or(AdministratorError::LedgerIntegrity)?,
    ))
}

fn receipt(
    input: &CertificateCompletionInputV2<'_>,
    received: u64,
    completed: u64,
) -> CertificateCompletionReceiptV2 {
    CertificateCompletionReceiptV2 {
        authorization_jti: input.authority_evidence.authorization_jti.clone(),
        commit_id: input.manager_commit_evidence.commit_id.clone(),
        authority_evidence_digest_sha256: input.authority_evidence.certificate_digest_sha256(),
        manager_commit_digest_sha256: input.manager_commit_evidence.certificate_digest_sha256(),
        disposition: input.authority_evidence.disposition.as_str().into(),
        received_at_epoch_s: received,
        completed_at_epoch_s: completed,
    }
}

fn closed_json<T: serde::Serialize + Validate>(value: &T) -> Result<String> {
    value
        .validate()
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    serde_json::to_string(value).map_err(|_| AdministratorError::LedgerIntegrity)
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| AdministratorError::Time)
}

fn constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(value, _)
            if value.code == rusqlite::ErrorCode::ConstraintViolation
    )
}
