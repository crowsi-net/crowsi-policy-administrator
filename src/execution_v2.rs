use crowsi_control_contracts::{
    CanonicalPayloadV1, IsolationCommandV2, PEP_EXECUTION_LEASE_SCHEMA_V2, Validate,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{
    AdministratorError, EnforcementPointV2, EnforcementStatusV2, PepExecutionLeaseV2,
    PolicyAdministrator, Result, clock_watermark,
};

impl PolicyAdministrator {
    /// Marks one committed command as dispatched and returns its immutable PEP lease.
    ///
    /// # Errors
    ///
    /// Rejects missing, expired, replayed, revoked, or corrupted reservations.
    pub fn begin_execution_v2(&mut self, command_jti: &str) -> Result<PepExecutionLeaseV2> {
        let now = self.clock.now();
        self.observe_time(&now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        clock_watermark::advance(&transaction, &now)?;
        let stored = transaction
            .query_row(
                "SELECT command_json, command_digest, reserved_at,
                        command_expires_at, state
                   FROM v2_enforcement_reservations WHERE command_jti = ?",
                [command_jti],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(AdministratorError::Replay)?;
        if stored.4 != "reserved" {
            return Err(AdministratorError::Replay);
        }
        let command: IsolationCommandV2 =
            serde_json::from_str(&stored.0).map_err(|_| AdministratorError::LedgerIntegrity)?;
        crate::stored_command_v2::verify(&self.policy, &self.trusted_keys, &command, &stored.1)?;
        if command.jti != command_jti
            || now.as_str() < command.issued_at.as_str()
            || now.as_str() >= stored.3.as_str()
        {
            return Err(AdministratorError::LedgerIntegrity);
        }
        verify_revocation(&transaction, &self.policy.identity_issuer, &command)?;
        let lease = PepExecutionLeaseV2 {
            schema: PEP_EXECUTION_LEASE_SCHEMA_V2.into(),
            reservation_id: command.release_reservation_id.clone(),
            command,
            command_digest: stored.1,
            reserved_at: stored.2,
        };
        lease
            .validate()
            .map_err(|error| AdministratorError::Contract(error.to_string()))?;
        let changed = transaction.execute(
            "UPDATE v2_enforcement_reservations SET state = 'executing'
              WHERE command_jti = ? AND state = 'reserved'",
            [command_jti],
        )?;
        if changed != 1 {
            return Err(AdministratorError::Replay);
        }
        transaction.commit()?;
        Ok(lease)
    }

    /// Executes one provider CAS and persists ambiguous transport results as unknown.
    ///
    /// # Errors
    ///
    /// Returns `OutcomeUnknown` after durably locking an indeterminate result.
    pub fn execute_v2<P: EnforcementPointV2>(
        &mut self,
        command_jti: &str,
        pep: &mut P,
    ) -> Result<EnforcementStatusV2> {
        let lease = self.begin_execution_v2(command_jti)?;
        match pep.compare_and_swap(&lease) {
            Ok(receipt) => match self.record_receipt_v2(&receipt) {
                Ok(status) => Ok(status),
                Err(error) => {
                    self.mark_result_unknown_v2(command_jti, &receipt.payload_digest())?;
                    Err(error)
                }
            },
            Err(uncertain) => {
                self.mark_result_unknown_v2(command_jti, uncertain.evidence_digest())?;
                Err(AdministratorError::OutcomeUnknown)
            }
        }
    }
}

fn verify_revocation(
    tx: &rusqlite::Transaction<'_>,
    issuer: &str,
    command: &IsolationCommandV2,
) -> Result<()> {
    let epoch = tx
        .query_row(
            "SELECT revocation_epoch FROM subject_revocation_epochs
              WHERE issuer = ? AND pairwise_subject = ?",
            params![issuer, command.pairwise_subject],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(AdministratorError::Revoked)?;
    if u64::try_from(epoch).ok() == Some(command.revocation_epoch) {
        Ok(())
    } else {
        Err(AdministratorError::Revoked)
    }
}
