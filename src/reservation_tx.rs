use crowsi_control_contracts::CanonicalPayloadV1;
use rusqlite::{ErrorCode, TransactionBehavior, params};

use crate::{
    AdministratorError, EnforcementReservation, PolicyAdministrator, ReservationInput, Result,
    clock_watermark,
    reserve::{action_name, channel_name},
    revocation,
};

impl PolicyAdministrator {
    pub(crate) fn commit_reservation(
        &mut self,
        input: &ReservationInput<'_>,
        now: &str,
        expected: i64,
        next: i64,
        policy_result: Result<()>,
    ) -> Result<EnforcementReservation> {
        let resource = &input.command.binding.resource;
        let command_digest = input.command.payload_digest();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        clock_watermark::advance(&transaction, now)?;
        revocation::reconcile(
            &transaction,
            &input.identity.issuer,
            &input.identity.pairwise_subject,
            input.policy_information.authoritative_revocation_epoch,
        )?;
        if let Err(error) = policy_result {
            transaction.commit()?;
            return Err(error);
        }
        transaction.execute(
            "INSERT OR IGNORE INTO resource_epochs VALUES (?, 0)",
            [resource],
        )?;
        let current: i64 = transaction.query_row(
            "SELECT isolation_epoch FROM resource_epochs WHERE resource = ?",
            [resource],
            |row| row.get(0),
        )?;
        if current != expected {
            transaction.commit()?;
            return Err(AdministratorError::EpochConflict);
        }
        let insert = transaction.execute(
            "INSERT INTO enforcement_reservations(
               command_jti, grant_jti, recovery_jti, resource, audience, action,
               purpose, channel, command_digest, policy_snapshot_id,
               policy_snapshot_digest, isolation_epoch, reserved_at,
               command_issued_at, command_expires_at, state
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved')",
            params![
                input.command.jti,
                input.grant.jti,
                input.recovery_authorization.map(|value| &value.jti),
                resource,
                input.command.binding.audience,
                action_name(input.command.binding.action),
                input.command.binding.purpose,
                channel_name(input.command.binding.channel),
                command_digest,
                input.policy_information.snapshot_id,
                input.policy_information.payload_digest(),
                next,
                now,
                input.command.issued_at,
                input.command.expires_at,
            ],
        );
        if let Err(error) = insert {
            return if constraint_violation(&error) {
                transaction.commit()?;
                Err(AdministratorError::Replay)
            } else {
                Err(AdministratorError::Storage(error))
            };
        }
        let changed = transaction.execute(
            "UPDATE resource_epochs SET isolation_epoch = ?
             WHERE resource = ? AND isolation_epoch = ?",
            params![next, resource, expected],
        )?;
        if changed != 1 {
            transaction.commit()?;
            return Err(AdministratorError::EpochConflict);
        }
        transaction.commit()?;
        Ok(EnforcementReservation {
            command_jti: input.command.jti.clone(),
            grant_jti: input.grant.jti.clone(),
            resource: resource.clone(),
            isolation_epoch: input.next_isolation_epoch,
            command_digest,
            expected_resource_version: input.command.expected_resource_version.clone(),
            expires_at: input.command.expires_at.clone(),
        })
    }
}

fn constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation
    )
}
