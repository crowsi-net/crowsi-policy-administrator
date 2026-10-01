use crowsi_control_contracts::CanonicalPayloadV1;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{
    AdministratorError, EnforcementReservationV2, PolicyAdministrator, ReservationInputV2, Result,
    clock_watermark,
    reservation_write_v2::{insert_reservation, to_i64},
    revocation,
};

impl PolicyAdministrator {
    pub(crate) fn commit_reservation_v2(
        &mut self,
        input: &ReservationInputV2<'_>,
        now: &str,
        policy_result: Result<()>,
    ) -> Result<EnforcementReservationV2> {
        let command = input.command;
        let digest = command.payload_digest();
        let json = serde_json::to_string(command)
            .map_err(|error| AdministratorError::Contract(error.to_string()))?;
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
        reject_replay_or_unresolved(&transaction, command)?;
        transaction.execute(
            "INSERT OR IGNORE INTO v2_resource_fences VALUES (?, ?, ?, ?, 0)",
            params![
                command.security_domain,
                command.deployment_id,
                command.provider,
                command.target_id
            ],
        )?;
        let current: i64 = transaction.query_row(
            "SELECT fence_epoch FROM v2_resource_fences
              WHERE security_domain = ? AND deployment_id = ?
                AND provider = ? AND target_id = ?",
            params![
                command.security_domain,
                command.deployment_id,
                command.provider,
                command.target_id
            ],
            |row| row.get(0),
        )?;
        let previous = to_i64(command.previous_fence_epoch)?;
        let next = to_i64(command.fence_epoch)?;
        if current != previous {
            transaction.commit()?;
            return Err(AdministratorError::FenceConflict);
        }
        insert_reservation(&transaction, input, now, &digest, &json)?;
        let changed = transaction.execute(
            "UPDATE v2_resource_fences SET fence_epoch = ?
              WHERE security_domain = ? AND deployment_id = ?
                AND provider = ? AND target_id = ? AND fence_epoch = ?",
            params![
                next,
                command.security_domain,
                command.deployment_id,
                command.provider,
                command.target_id,
                previous
            ],
        )?;
        if changed != 1 {
            return Err(AdministratorError::FenceConflict);
        }
        transaction.commit()?;
        Ok(EnforcementReservationV2 {
            command_jti: command.jti.clone(),
            release_reservation_id: command.release_reservation_id.clone(),
            security_domain: command.security_domain.clone(),
            deployment_id: command.deployment_id.clone(),
            target_id: command.target_id.clone(),
            fence_epoch: command.fence_epoch,
            command_digest: digest,
            expected_resource_version: command.expected_resource_version.clone(),
            expires_at: command.expires_at.clone(),
        })
    }
}

fn reject_replay_or_unresolved(
    tx: &rusqlite::Transaction<'_>,
    command: &crowsi_control_contracts::IsolationCommandV2,
) -> Result<()> {
    let replay = tx
        .query_row(
            "SELECT 1 FROM v2_enforcement_reservations
              WHERE command_jti = ? OR grant_jti = ? OR release_id = ?
                 OR release_digest = ? OR release_reservation_id = ?",
            params![
                command.jti,
                command.enforcement_grant_jti,
                command.release_id,
                command.release_digest,
                command.release_reservation_id
            ],
            |_| Ok(()),
        )
        .optional()?;
    if replay.is_some() {
        return Err(AdministratorError::Replay);
    }
    let unresolved = tx
        .query_row(
            "SELECT 1 FROM v2_enforcement_reservations
              WHERE security_domain = ? AND deployment_id = ?
                AND provider = ? AND target_id = ?
                AND state IN ('reserved', 'executing', 'result-unknown')",
            params![
                command.security_domain,
                command.deployment_id,
                command.provider,
                command.target_id
            ],
            |_| Ok(()),
        )
        .optional()?;
    if unresolved.is_some() {
        Err(AdministratorError::OutcomeUnknown)
    } else {
        Ok(())
    }
}
