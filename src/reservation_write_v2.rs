use rusqlite::{ErrorCode, params};

use crowsi_control_contracts::CanonicalPayloadV1;

use crate::{
    AdministratorError, ReservationInputV2, Result,
    reserve::{action_name, channel_name},
};

pub(crate) fn insert_reservation(
    tx: &rusqlite::Transaction<'_>,
    input: &ReservationInputV2<'_>,
    now: &str,
    digest: &str,
    json: &str,
) -> Result<()> {
    let command = input.command;
    let result = tx.execute(
        "INSERT INTO v2_enforcement_reservations(
           command_jti, grant_jti, release_id, release_digest,
           release_reservation_id, checkpoint_id, checkpoint_digest,
           checkpoint_sequence, security_domain, deployment_id, incident_id,
           target_id, provider, audience, action, purpose, channel,
           command_digest, command_json, previous_fence_epoch, fence_epoch,
           expected_resource_version, policy_snapshot_id, policy_snapshot_digest,
           reserved_at, command_issued_at, command_expires_at, state
         ) VALUES (
           ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
           ?, ?, ?, ?, ?, 'reserved'
         )",
        params![
            command.jti,
            input.grant.jti,
            command.release_id,
            command.release_digest,
            command.release_reservation_id,
            command.checkpoint_id,
            command.checkpoint_digest,
            to_i64(command.checkpoint_sequence)?,
            command.security_domain,
            command.deployment_id,
            command.incident_id,
            command.target_id,
            command.provider,
            command.binding.audience,
            action_name(command.binding.action),
            command.binding.purpose,
            channel_name(command.binding.channel),
            digest,
            json,
            to_i64(command.previous_fence_epoch)?,
            to_i64(command.fence_epoch)?,
            command.expected_resource_version,
            input.policy_information.snapshot_id,
            input.policy_information.payload_digest(),
            now,
            command.issued_at,
            command.expires_at,
        ],
    );
    match result {
        Ok(1) => Ok(()),
        Ok(_) => Err(AdministratorError::LedgerIntegrity),
        Err(error) if constraint_violation(&error) => Err(AdministratorError::Replay),
        Err(error) => Err(AdministratorError::Storage(error)),
    }
}

pub(crate) fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| AdministratorError::FenceConflict)
}

fn constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation
    )
}
