use crowsi_control_contracts::{CertificatePayloadV2, Validate};
use rusqlite::{OptionalExtension, Transaction};

use crate::{
    AdministratorError, CertificateCompletionInputV2, Result,
    certificate_completion_inbox_v2::CompletionInboxRecord,
};

pub(crate) fn find_exact(
    tx: &Transaction<'_>,
    input: &CertificateCompletionInputV2<'_>,
) -> Result<Option<CompletionInboxRecord>> {
    let authority_json = closed_json(input.authority_evidence)?;
    let manager_json = closed_json(input.manager_commit_evidence)?;
    let found = tx
        .query_row(
            "SELECT commit_id, authority_evidence_id,
                    authority_evidence_digest_sha256, manager_commit_digest_sha256,
                    authority_evidence_json, manager_commit_json, disposition,
                    received_at_epoch_s, recovery_deadline_epoch_s, state,
                    completed_at_epoch_s
               FROM certificate_v2_completion_inbox
              WHERE authorization_jti = ?",
            [&input.authority_evidence.authorization_jti],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = found else {
        return Ok(None);
    };
    let exact = row.0 == input.manager_commit_evidence.commit_id
        && row.1 == input.authority_evidence.evidence_id
        && row.2 == input.authority_evidence.certificate_digest_sha256()
        && row.3 == input.manager_commit_evidence.certificate_digest_sha256()
        && row.4 == authority_json
        && row.5 == manager_json
        && row.6 == input.authority_evidence.disposition.as_str();
    if !exact {
        return Err(AdministratorError::Replay);
    }
    Ok(Some(CompletionInboxRecord {
        received_at_epoch_s: number(row.7)?,
        recovery_deadline_epoch_s: number(row.8)?,
        state: row.9,
        completed_at_epoch_s: row.10.map(number).transpose()?,
    }))
}

fn closed_json<T: serde::Serialize + Validate>(value: &T) -> Result<String> {
    value
        .validate()
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    serde_json::to_string(value).map_err(|_| AdministratorError::LedgerIntegrity)
}

fn number(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| AdministratorError::LedgerIntegrity)
}
