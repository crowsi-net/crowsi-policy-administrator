use rusqlite::TransactionBehavior;

use crate::{
    AdministratorError, CertificateCompletionInputV2, CertificateCompletionReceiptV2,
    CertificatePolicyAdministratorV2, Result, certificate_completion_inbox_v2,
    certificate_completion_load_v2, certificate_completion_store_v2,
    certificate_completion_verify_v2, clock_watermark,
};

impl CertificatePolicyAdministratorV2 {
    pub(crate) fn prepare_certificate_completion_v2(
        &mut self,
        input: &CertificateCompletionInputV2<'_>,
    ) -> Result<Option<CertificateCompletionReceiptV2>> {
        let authorization_jti = &input.authority_evidence.authorization_jti;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = self.clock.now();
        let now_epoch_s = crate::clock::epoch_seconds(&now)?;
        clock_watermark::advance(&transaction, &now)?;
        if let Some(record) = certificate_completion_inbox_v2::find_exact(&transaction, input)? {
            let receipt = if record.state == "completed" {
                Some(certificate_completion_inbox_v2::completed_receipt(
                    input, &record,
                )?)
            } else if record.state == "prepared" {
                None
            } else {
                return Err(AdministratorError::LedgerIntegrity);
            };
            transaction.commit()?;
            return Ok(receipt);
        }
        let reservation = certificate_completion_load_v2::current(&transaction, authorization_jti)?;
        certificate_completion_verify_v2::verify(
            &transaction,
            &self.policy,
            &self.trusted_keys,
            &reservation,
            input,
            now_epoch_s,
        )?;
        certificate_completion_inbox_v2::insert_prepared(
            &transaction,
            input,
            now_epoch_s,
            self.policy.max_completion_recovery_seconds,
        )?;
        transaction.commit()?;
        Ok(None)
    }

    pub(super) fn finalize_certificate_completion_v2(
        &mut self,
        input: &CertificateCompletionInputV2<'_>,
    ) -> Result<CertificateCompletionReceiptV2> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = certificate_completion_inbox_v2::find_exact(&transaction, input)?
            .ok_or(AdministratorError::LedgerIntegrity)?;
        if record.state == "completed" {
            let receipt = certificate_completion_inbox_v2::completed_receipt(input, &record)?;
            transaction.commit()?;
            return Ok(receipt);
        }
        if record.state != "prepared" {
            return Err(AdministratorError::LedgerIntegrity);
        }
        let now = self.clock.now();
        let now_epoch_s = crate::clock::epoch_seconds(&now)?;
        clock_watermark::advance(&transaction, &now)?;
        if now_epoch_s > record.recovery_deadline_epoch_s {
            return Err(AdministratorError::Time);
        }
        let reservation = certificate_completion_load_v2::current(
            &transaction,
            &input.authority_evidence.authorization_jti,
        )?;
        certificate_completion_verify_v2::verify(
            &transaction,
            &self.policy,
            &self.trusted_keys,
            &reservation,
            input,
            record.received_at_epoch_s,
        )?;
        let finalize_time = self.clock.now();
        let finalize_epoch_s = crate::clock::epoch_seconds(&finalize_time)?;
        clock_watermark::advance(&transaction, &finalize_time)?;
        if finalize_epoch_s > record.recovery_deadline_epoch_s {
            return Err(AdministratorError::Time);
        }
        certificate_completion_store_v2::apply(
            &transaction,
            &reservation,
            input,
            finalize_epoch_s,
        )?;
        let receipt = certificate_completion_inbox_v2::complete(
            &transaction,
            input,
            &record,
            finalize_epoch_s,
        )?;
        transaction.commit()?;
        Ok(receipt)
    }
}
