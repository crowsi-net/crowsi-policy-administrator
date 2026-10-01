use rusqlite::{TransactionBehavior, params};

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2, CertificatePolicyAdministratorV2,
    Result, certificate_expiry_integrity_v2, certificate_fence_v2, certificate_lifecycle_epoch_v2,
    clock_watermark,
};

impl CertificatePolicyAdministratorV2 {
    /// Abandons a signed authorization that expired before it was ever released.
    ///
    /// The signed handoff remains in the private ledger as audit evidence, while
    /// pending counters are discarded without rolling back committed counters.
    ///
    /// # Errors
    ///
    /// Rejects non-ready, released, non-expired, replayed, or corrupted state.
    pub fn expire_unreleased_certificate_authorization_v2(
        &mut self,
        _channel: &AuthenticatedCertificateManagerChannelV2,
        authorization_jti: &str,
    ) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = self.clock.now();
        let now_epoch_s = crate::clock::epoch_seconds(&now)?;
        clock_watermark::advance(&transaction, &now)?;
        let expiring = certificate_expiry_integrity_v2::load_and_verify(
            &transaction,
            &self.policy.authorization_signer_public_key_base64,
            authorization_jti,
        )?;
        if now_epoch_s < expiring.expires_at_epoch_s {
            return Err(AdministratorError::Time);
        }
        let command = &expiring.lease.command;
        let fence = certificate_fence_v2::discard(&transaction, command)?;
        let lifecycle = certificate_lifecycle_epoch_v2::discard(&transaction, command)?;
        let expected_fence = usize::from(!matches!(
            command.action,
            crowsi_control_contracts::CertificateActionV2::CertificateStatus
                | crowsi_control_contracts::CertificateActionV2::OperationStatus
        ));
        let expected_lifecycle =
            usize::from(command.action == crowsi_control_contracts::CertificateActionV2::Revoke);
        if fence != expected_fence || lifecycle != expected_lifecycle {
            return Err(AdministratorError::LedgerIntegrity);
        }
        let reservation = transaction.execute(
            "UPDATE certificate_v2_reservations SET state = 'abandoned'
              WHERE authorization_jti = ? AND state = 'reserved'
                AND lease_digest_sha256 IS NULL",
            [authorization_jti],
        )?;
        let handoff = transaction.execute(
            "UPDATE certificate_v2_signing_handoffs SET state = 'expired-unreleased'
              WHERE authorization_jti = ? AND state = 'ready'
                AND signed_authorization_json IS NOT NULL",
            params![authorization_jti],
        )?;
        if reservation != 1 || handoff != 1 {
            return Err(AdministratorError::Replay);
        }
        transaction.commit()?;
        Ok(())
    }
}
