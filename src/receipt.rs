use crowsi_control_contracts::{
    CanonicalPayloadV1, EnforcementOutcome, EnforcementReceiptV1, Validate,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{
    AdministratorError, ArtifactRole, EnforcementStatus, KeyScope, PolicyAdministrator, Result,
    clock_watermark, receipt_model::StoredReservation,
};

impl PolicyAdministrator {
    /// Records a trusted PEP receipt without treating it as independent proof.
    ///
    /// # Errors
    ///
    /// Rejects unsigned, conflicting, or unbound receipts and preserves the
    /// original reservation for investigation.
    pub fn record_receipt(&mut self, receipt: &EnforcementReceiptV1) -> Result<EnforcementStatus> {
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
        let stored = transaction
            .query_row(
                "SELECT grant_jti, resource, audience, action, purpose, channel,
                        isolation_epoch, state, receipt_id, receipt_digest,
                        reserved_at, command_expires_at
                   FROM enforcement_reservations WHERE command_jti = ?",
                [&receipt.command_jti],
                StoredReservation::from_row,
            )
            .optional()?
            .ok_or(AdministratorError::ReceiptMismatch)?;
        stored.verify(receipt, &now)?;
        let digest = receipt.payload_digest();
        if stored.state != "reserved" {
            if stored.receipt_id.as_deref() == Some(&receipt.receipt_id)
                && stored.receipt_digest.as_deref() == Some(&digest)
            {
                transaction.commit()?;
                return Ok(stored.status(&receipt.command_jti));
            }
            return Err(AdministratorError::ReceiptMismatch);
        }
        let outcome = outcome_name(receipt.outcome);
        let changed = transaction.execute(
            "UPDATE enforcement_reservations
                SET state = ?, outcome = ?, receipt_id = ?, receipt_digest = ?
              WHERE command_jti = ? AND state = 'reserved'",
            params![
                outcome,
                outcome,
                receipt.receipt_id,
                digest,
                receipt.command_jti
            ],
        )?;
        if changed != 1 {
            return Err(AdministratorError::Replay);
        }
        let status = EnforcementStatus {
            resource: stored.resource,
            isolation_epoch: stored.isolation_epoch,
            command_jti: receipt.command_jti.clone(),
            state: outcome.to_owned(),
            outcome: Some(outcome.to_owned()),
        };
        transaction.commit()?;
        Ok(status)
    }

    /// Returns the latest reserved or completed action for one resource.
    ///
    /// # Errors
    ///
    /// Returns `ReceiptMismatch` when no action exists for the resource.
    pub fn status(&self, resource: &str) -> Result<EnforcementStatus> {
        self.connection
            .query_row(
                "SELECT resource, isolation_epoch, command_jti, state, outcome
                   FROM enforcement_reservations
                  WHERE resource = ? ORDER BY isolation_epoch DESC LIMIT 1",
                [resource],
                |row| {
                    Ok(EnforcementStatus {
                        resource: row.get(0)?,
                        isolation_epoch: u64::try_from(row.get::<_, i64>(1)?)
                            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, -1))?,
                        command_jti: row.get(2)?,
                        state: row.get(3)?,
                        outcome: row.get(4)?,
                    })
                },
            )
            .optional()?
            .ok_or(AdministratorError::ReceiptMismatch)
    }
}

pub(crate) fn outcome_name(outcome: EnforcementOutcome) -> &'static str {
    match outcome {
        EnforcementOutcome::Applied => "applied",
        EnforcementOutcome::Rejected => "rejected",
        EnforcementOutcome::Failed => "failed",
        EnforcementOutcome::Partial => "partial",
    }
}
