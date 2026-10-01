use crowsi_control_contracts::{CertificateApprovalEvidenceV2, CertificatePayloadV2};
use rusqlite::{ErrorCode, Transaction, params};

use crate::{AdministratorError, Result};

pub(crate) fn insert(
    tx: &Transaction<'_>,
    pa_reservation_id: &str,
    evidence: &CertificateApprovalEvidenceV2,
) -> Result<()> {
    let result = tx.execute(
        "INSERT INTO certificate_v2_approval_uses VALUES (?, ?, ?, ?, ?)",
        params![
            evidence.approval_id,
            evidence.certificate_digest_sha256(),
            evidence.challenge_id,
            evidence.challenge_nonce_base64,
            pa_reservation_id
        ],
    );
    match result {
        Ok(1) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(value, _))
            if value.code == ErrorCode::ConstraintViolation =>
        {
            Err(AdministratorError::Replay)
        }
        Ok(_) => Err(AdministratorError::LedgerIntegrity),
        Err(error) => Err(AdministratorError::Storage(error)),
    }
}
