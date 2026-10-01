use crowsi_control_contracts::{CanonicalPayloadV1, EnforcementReceiptV2, Validate};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{
    AdministratorError, ArtifactRole, EnforcementStatusV2, KeyScope, PolicyAdministrator, Result,
    clock_watermark, receipt::outcome_name, receipt_model_v2::StoredReservationV2,
};

impl PolicyAdministrator {
    /// Records a definitive V2 receipt for a currently executing command.
    ///
    /// # Errors
    ///
    /// Rejects unsigned, stale, non-CAS, replayed, or cross-bound receipts.
    pub fn record_receipt_v2(
        &mut self,
        receipt: &EnforcementReceiptV2,
    ) -> Result<EnforcementStatusV2> {
        self.complete_receipt_v2(receipt, "executing")
    }

    /// Resolves an unknown result only with the exact signed provider receipt.
    ///
    /// # Errors
    ///
    /// Rejects any receipt not bound to the locked command and fence.
    pub fn reconcile_unknown_v2(
        &mut self,
        receipt: &EnforcementReceiptV2,
    ) -> Result<EnforcementStatusV2> {
        self.complete_receipt_v2(receipt, "result-unknown")
    }

    fn complete_receipt_v2(
        &mut self,
        receipt: &EnforcementReceiptV2,
        required_state: &str,
    ) -> Result<EnforcementStatusV2> {
        let now = self.clock.now();
        self.observe_time(&now)?;
        receipt
            .validate()
            .map_err(|error| AdministratorError::Contract(error.to_string()))?;
        self.trusted_keys.verify(
            ArtifactRole::Receipt,
            &KeyScope::Provider(receipt.provider.clone()),
            receipt,
            &receipt.signed,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        clock_watermark::advance(&transaction, &now)?;
        let stored = load(&transaction, &receipt.command_jti)?;
        crate::stored_command_v2::verify(
            &self.policy,
            &self.trusted_keys,
            &stored.command,
            &stored.command_digest,
        )?;
        stored.verify(receipt, &now)?;
        let digest = receipt.payload_digest();
        if stored.state != required_state {
            if stored.receipt_id.as_deref() == Some(&receipt.receipt_id)
                && stored.receipt_digest.as_deref() == Some(&digest)
                && crate::persisted_receipt_v2::matches(&transaction, receipt, &digest)?
            {
                transaction.commit()?;
                return Ok(stored.status());
            }
            return Err(AdministratorError::ReceiptMismatch);
        }
        let outcome = outcome_name(receipt.outcome);
        crate::persisted_receipt_v2::insert(&transaction, receipt, &digest)?;
        let changed = transaction.execute(
            "UPDATE v2_enforcement_reservations
                SET state = ?, outcome = ?, receipt_id = ?, receipt_digest = ?
              WHERE command_jti = ? AND state = ?",
            params![
                outcome,
                outcome,
                receipt.receipt_id,
                digest,
                receipt.command_jti,
                required_state
            ],
        )?;
        if changed != 1 {
            return Err(AdministratorError::Replay);
        }
        transaction.commit()?;
        self.status_v2(&receipt.command_jti)
    }

    /// Returns one command's durable V2 state.
    ///
    /// # Errors
    ///
    /// Returns `ReceiptMismatch` when the command is not in the ledger.
    pub fn status_v2(&self, command_jti: &str) -> Result<EnforcementStatusV2> {
        let stored = self
            .connection
            .query_row(
                "SELECT command_json, command_digest, reserved_at,
                        command_expires_at, state, outcome,
                        receipt_id, receipt_digest
                   FROM v2_enforcement_reservations WHERE command_jti = ?",
                [command_jti],
                StoredReservationV2::from_row,
            )
            .optional()?
            .ok_or(AdministratorError::ReceiptMismatch)?;
        crate::stored_command_v2::verify(
            &self.policy,
            &self.trusted_keys,
            &stored.command,
            &stored.command_digest,
        )?;
        crate::persisted_receipt_v2::verify_status(
            &self.connection,
            &self.policy,
            &self.trusted_keys,
            &stored,
            &self.clock.now(),
        )?;
        Ok(stored.status())
    }
}

fn load(transaction: &rusqlite::Transaction<'_>, command_jti: &str) -> Result<StoredReservationV2> {
    transaction
        .query_row(
            "SELECT command_json, command_digest, reserved_at,
                    command_expires_at, state, outcome,
                    receipt_id, receipt_digest
               FROM v2_enforcement_reservations WHERE command_jti = ?",
            [command_jti],
            StoredReservationV2::from_row,
        )
        .optional()?
        .ok_or(AdministratorError::ReceiptMismatch)
}
