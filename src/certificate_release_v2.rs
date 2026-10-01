use crowsi_control_contracts::{
    CertificateExecutionLeaseV2, CertificatePayloadV2, SignedCertificateExecutionAuthorizationV2,
    Validate, package_signed_certificate_authorization_v2,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2, CertificatePolicyAdministratorV2,
    Result, certificate_signing_store_v2, clock_watermark,
};

impl CertificatePolicyAdministratorV2 {
    /// Atomically releases a durably signed authorization to the manager.
    ///
    /// A repeated call after response loss returns the same stored artifact.
    ///
    /// # Errors
    ///
    /// Rejects unsigned, expired, tampered, replayed, or concurrently fenced state.
    pub fn release_signed_certificate_execution_v2(
        &mut self,
        _channel: &AuthenticatedCertificateManagerChannelV2,
        authorization_jti: &str,
    ) -> Result<SignedCertificateExecutionAuthorizationV2> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = self.clock.now();
        let now_epoch_s = crate::clock::epoch_seconds(&now)?;
        clock_watermark::advance(&transaction, &now)?;
        let row = transaction
            .query_row(
                "SELECT h.signed_authorization_json, h.lease_json, h.state,
                        h.lease_digest_sha256, r.state, r.expires_at_epoch_s
                   FROM certificate_v2_signing_handoffs h
                   JOIN certificate_v2_reservations r USING(pa_reservation_id)
                  WHERE h.authorization_jti = ?",
                [authorization_jti],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or(AdministratorError::Replay)?;
        let signed_json = row
            .0
            .ok_or(AdministratorError::CertificateAuthorizationUnavailable)?;
        let signed: SignedCertificateExecutionAuthorizationV2 =
            serde_json::from_str(&signed_json).map_err(|_| AdministratorError::LedgerIntegrity)?;
        let lease: CertificateExecutionLeaseV2 =
            serde_json::from_str(&row.1).map_err(|_| AdministratorError::LedgerIntegrity)?;
        verify_stored(
            &self.policy.authorization_signer_public_key_base64,
            &signed,
            &lease,
            &row.3,
        )?;
        if row.2 == "accepted" {
            if !matches!(row.4.as_str(), "executing" | "result-unknown" | "consumed") {
                return Err(AdministratorError::LedgerIntegrity);
            }
            transaction.commit()?;
            return Ok(signed);
        }
        if row.2 == "released-pending-accept" {
            if row.4 != "reserved" || row.5 < 0 {
                return Err(AdministratorError::LedgerIntegrity);
            }
            transaction.commit()?;
            return Ok(signed);
        }
        if row.2 != "ready" || row.4 != "reserved" {
            return Err(AdministratorError::Replay);
        }
        if u64::try_from(row.5)
            .ok()
            .is_none_or(|expiry| now_epoch_s >= expiry)
        {
            return Err(AdministratorError::Time);
        }
        let handoff = transaction.execute(
            "UPDATE certificate_v2_signing_handoffs
                SET state = 'released-pending-accept', released_at_epoch_s = ?
              WHERE authorization_jti = ? AND state = 'ready'",
            params![
                i64::try_from(now_epoch_s).map_err(|_| AdministratorError::Time)?,
                authorization_jti
            ],
        )?;
        if handoff != 1 {
            return Err(AdministratorError::Replay);
        }
        transaction.commit()?;
        Ok(signed)
    }
}

pub(crate) fn verify_stored(
    public_key_base64: &str,
    signed: &SignedCertificateExecutionAuthorizationV2,
    lease: &CertificateExecutionLeaseV2,
    digest: &str,
) -> Result<()> {
    signed
        .validate()
        .map_err(|_| AdministratorError::LedgerIntegrity)?;
    lease
        .validate()
        .map_err(|_| AdministratorError::LedgerIntegrity)?;
    if lease.certificate_digest_sha256() != digest || signed.lease_digest_sha256() != digest {
        return Err(AdministratorError::LedgerIntegrity);
    }
    certificate_signing_store_v2::verify_signature(
        public_key_base64,
        digest,
        signed.signature_base64(),
    )?;
    let expected = package_signed_certificate_authorization_v2(lease, signed.signature_base64())
        .map_err(|_| AdministratorError::LedgerIntegrity)?;
    (expected == *signed)
        .then_some(())
        .ok_or(AdministratorError::LedgerIntegrity)
}
