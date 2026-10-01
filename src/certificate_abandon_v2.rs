use crowsi_control_contracts::{CertificateActionV2, CertificateExecutionCommandV2};
use rusqlite::{OptionalExtension, TransactionBehavior};

use crate::{
    AdministratorError, CertificatePolicyAdministratorV2, Result, certificate_fence_v2,
    certificate_lifecycle_epoch_v2, clock_watermark,
};

impl CertificatePolicyAdministratorV2 {
    /// Abandons an expired reservation that was never handed to the manager.
    ///
    /// Only the exact pending proposal is removed. Committed authorization and
    /// lifecycle counters never move backwards.
    ///
    /// # Errors
    ///
    /// Rejects non-expired, invoked, replayed, or concurrently changed state.
    pub fn abandon_expired_certificate_reservation_v2(
        &mut self,
        authorization_jti: &str,
    ) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = self.clock.now();
        let now_epoch_s = crate::clock::epoch_seconds(&now)?;
        clock_watermark::advance(&transaction, &now)?;
        let row = transaction
            .query_row(
                "SELECT command_json, expires_at_epoch_s
                  FROM certificate_v2_reservations
                  WHERE authorization_jti = ? AND state = 'reserved'
                    AND lease_digest_sha256 IS NULL
                    AND NOT EXISTS (
                      SELECT 1 FROM certificate_v2_signing_handoffs h
                       WHERE h.authorization_jti = certificate_v2_reservations.authorization_jti
                    )",
                [authorization_jti],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .ok_or(AdministratorError::Replay)?;
        if u64::try_from(row.1)
            .ok()
            .is_none_or(|expires| now_epoch_s < expires)
        {
            return Err(AdministratorError::Time);
        }
        let command: CertificateExecutionCommandV2 =
            serde_json::from_str(&row.0).map_err(|_| AdministratorError::LedgerIntegrity)?;
        let expected_fence = usize::from(!matches!(
            command.action,
            CertificateActionV2::CertificateStatus | CertificateActionV2::OperationStatus
        ));
        let expected_lifecycle = usize::from(command.action == CertificateActionV2::Revoke);
        if certificate_fence_v2::discard(&transaction, &command)? != expected_fence {
            return Err(AdministratorError::FenceConflict);
        }
        if certificate_lifecycle_epoch_v2::discard(&transaction, &command)? != expected_lifecycle {
            return Err(AdministratorError::EpochConflict);
        }
        let changed = transaction.execute(
            "UPDATE certificate_v2_reservations SET state = 'abandoned'
              WHERE authorization_jti = ? AND state = 'reserved'
                AND lease_digest_sha256 IS NULL",
            [authorization_jti],
        )?;
        if changed != 1 {
            return Err(AdministratorError::Replay);
        }
        transaction.commit()?;
        Ok(())
    }
}
