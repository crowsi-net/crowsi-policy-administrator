use crowsi_control_contracts::CertificatePayloadV2;
use rusqlite::{OptionalExtension, Transaction, params};

use crate::{
    AdministratorError, CertificateHandoffInputV2, CertificateHandoffReceiptAckV2, Result,
};

pub(crate) fn existing(
    tx: &Transaction<'_>,
    input: &CertificateHandoffInputV2<'_>,
) -> Result<Option<CertificateHandoffReceiptAckV2>> {
    let evidence = input.evidence;
    let json = serde_json::to_string(evidence).map_err(|_| AdministratorError::LedgerIntegrity)?;
    let row = tx
        .query_row(
            "SELECT receipt_id, nonce_base64, evidence_digest_sha256,
                    evidence_json, disposition, recorded_at_epoch_s, resulting_state
               FROM certificate_v2_handoff_receipts WHERE authorization_jti = ?",
            [&evidence.authorization_jti],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let digest = evidence.certificate_digest_sha256();
    if row.0 != evidence.receipt_id
        || row.1 != evidence.nonce_base64
        || row.2 != digest
        || row.3 != json
        || row.4 != evidence.disposition.as_str()
    {
        return Err(AdministratorError::Replay);
    }
    Ok(Some(ack(evidence, digest, row.6, number(row.5)?)))
}

pub(crate) fn store(
    tx: &Transaction<'_>,
    input: &CertificateHandoffInputV2<'_>,
    resulting_state: &str,
    recorded_at: u64,
) -> Result<CertificateHandoffReceiptAckV2> {
    let evidence = input.evidence;
    let digest = evidence.certificate_digest_sha256();
    tx.execute(
        "INSERT INTO certificate_v2_handoff_receipts
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            evidence.authorization_jti,
            evidence.receipt_id,
            evidence.nonce_base64,
            digest,
            serde_json::to_string(evidence).map_err(|_| AdministratorError::LedgerIntegrity)?,
            evidence.disposition.as_str(),
            i64::try_from(recorded_at).map_err(|_| AdministratorError::Time)?,
            resulting_state
        ],
    )
    .map_err(|error| {
        if constraint(&error) {
            AdministratorError::Replay
        } else {
            AdministratorError::Storage(error)
        }
    })?;
    Ok(ack(evidence, digest, resulting_state.into(), recorded_at))
}

fn ack(
    evidence: &crowsi_control_contracts::CertificateManagerHandoffEvidenceV2,
    digest: String,
    resulting_state: String,
    recorded_at: u64,
) -> CertificateHandoffReceiptAckV2 {
    CertificateHandoffReceiptAckV2 {
        authorization_jti: evidence.authorization_jti.clone(),
        receipt_id: evidence.receipt_id.clone(),
        evidence_digest_sha256: digest,
        disposition: evidence.disposition.as_str().into(),
        resulting_state,
        recorded_at_epoch_s: recorded_at,
    }
}

fn number(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| AdministratorError::LedgerIntegrity)
}

fn constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(value, _)
            if value.code == rusqlite::ErrorCode::ConstraintViolation
    )
}
