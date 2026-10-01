use crowsi_control_contracts::{CertificateManagerHandoffDispositionV2, Validate};
use rusqlite::TransactionBehavior;

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2, CertificateHandoffInputV2,
    CertificateHandoffReceiptAckV2, CertificatePolicyAdministratorV2, Result,
    certificate_handoff_load_v2, certificate_handoff_receipt_v2, certificate_handoff_transition_v2,
    certificate_handoff_verify_v2, clock_watermark,
};

impl CertificatePolicyAdministratorV2 {
    /// Applies a durable manager acceptance or post-expiry non-acceptance receipt.
    ///
    /// Fence and lifecycle counters advance only after an independently signed,
    /// manager-durable acceptance receipt is verified.
    ///
    /// # Errors
    ///
    /// Rejects altered replay, stale evidence, wrong manager scope, or row drift.
    pub fn accept_released_certificate_execution_v2(
        &mut self,
        _channel: &AuthenticatedCertificateManagerChannelV2,
        input: &CertificateHandoffInputV2<'_>,
    ) -> Result<CertificateHandoffReceiptAckV2> {
        input
            .evidence
            .validate()
            .map_err(|error| AdministratorError::Contract(error.to_string()))?;
        let policy = &self.policy;
        let trusted_keys = &self.trusted_keys;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(ack) = certificate_handoff_receipt_v2::existing(&transaction, input)? {
            transaction.commit()?;
            return Ok(ack);
        }
        let pending = certificate_handoff_load_v2::load(
            &transaction,
            &self.policy.authorization_signer_public_key_base64,
            &input.evidence.authorization_jti,
        )?;
        let now = self.clock.now();
        let now_epoch_s = crate::clock::epoch_seconds(&now)?;
        clock_watermark::advance(&transaction, &now)?;
        certificate_handoff_verify_v2::verify(policy, trusted_keys, &pending, input, now_epoch_s)?;
        let final_time = self.clock.now();
        let final_epoch_s = crate::clock::epoch_seconds(&final_time)?;
        clock_watermark::advance(&transaction, &final_time)?;
        if final_epoch_s >= input.evidence.expires_at_epoch_s {
            return Err(AdministratorError::Time);
        }
        if input.evidence.disposition == CertificateManagerHandoffDispositionV2::Accepted
            && final_epoch_s >= pending.command_expires_at_epoch_s
        {
            return Err(AdministratorError::Time);
        }
        let resulting_state =
            certificate_handoff_transition_v2::apply(&transaction, &pending, input)?;
        let ack = certificate_handoff_receipt_v2::store(
            &transaction,
            input,
            &resulting_state,
            final_epoch_s,
        )?;
        transaction.commit()?;
        Ok(ack)
    }
}
