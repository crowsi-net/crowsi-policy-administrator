use crowsi_control_contracts::CertificatePayloadV2;
use rusqlite::{ErrorCode, Transaction, named_params};

use crate::{AdministratorError, CertificateReservationInputV2, Result};

pub(crate) fn insert(
    tx: &Transaction<'_>,
    input: &CertificateReservationInputV2<'_>,
    reserved_at_epoch_s: u64,
) -> Result<String> {
    let command = input.command;
    let binding = &command.binding;
    let deployment = &binding.deployment;
    let identity = &binding.identity;
    let target = &binding.target;
    let digest = command.certificate_digest_sha256();
    let json = serde_json::to_string(command)
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    let decision_json = serde_json::to_string(input.decision)
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    let grant_json = serde_json::to_string(input.grant)
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    let result = tx.execute(
        "INSERT INTO certificate_v2_reservations(
           authorization_jti, authorization_id, pa_reservation_id, operation_id,
           grant_jti, grant_id,
           decision_id, approval_id, request_digest_sha256,
           authorization_command_digest_sha256, related_authorization_jti,
           action, fence_scope, security_domain, deployment_id, release_id,
           release_digest_sha256, deployment_provenance_ref, policy_id,
           policy_digest_sha256, pairwise_subject, service_id, workload, profile,
           requester_pairwise_subject, approver_pairwise_subject, identity_revocation_epoch,
           previous_identity_revocation_epoch,
           target_resource_id, provider, previous_fence, current_fence,
           expected_resource_version, command_json, decision_json, grant_json,
           reserved_at_epoch_s, issued_at_epoch_s, expires_at_epoch_s, state,
           previous_lifecycle_revocation_epoch, lifecycle_revocation_epoch
         ) VALUES (
           :jti, :authorization_id, :pa_reservation_id, :operation_id,
           :grant_jti, :grant_id,
           :decision_id, :approval_id, :request_digest, :command_digest, :related,
           :action, :scope, :domain, :deployment, :release_id, :release_digest,
           :reservation_id, :policy_id, :policy_digest, :subject, :service_id,
           :workload, :profile, :requester, :approver, :revocation,
           :previous_revocation, :target, :provider,
           :previous_fence, :current_fence, :version, :json, :decision_json,
           :grant_json, :reserved_at, :issued_at, :expires_at, 'reserved',
           :previous_lifecycle_revocation, :lifecycle_revocation
         )",
        named_params! {
            ":jti": command.jti,
            ":authorization_id": command.authorization_id,
            ":pa_reservation_id": command.pa_reservation_id,
            ":operation_id": command.operation_id,
            ":grant_jti": input.grant.jti,
            ":grant_id": command.grant_id,
            ":decision_id": command.decision_id,
            ":approval_id": binding.approval_id,
            ":request_digest": command.request_digest_sha256,
            ":command_digest": digest,
            ":related": command.related_authorization_jti,
            ":action": command.action.as_str(),
            ":scope": command.action.fence_scope(),
            ":domain": deployment.security_domain,
            ":deployment": deployment.deployment_id,
            ":release_id": deployment.release_id,
            ":release_digest": deployment.release_digest_sha256,
            ":reservation_id": deployment.deployment_provenance_ref,
            ":policy_id": binding.policy_id,
            ":policy_digest": binding.policy_digest_sha256,
            ":subject": identity.pairwise_subject,
            ":service_id": target.service_id,
            ":workload": identity.workload,
            ":profile": identity.requester_profile,
            ":requester": identity.requester_pairwise_subject,
            ":approver": identity.approver_pairwise_subject,
            ":revocation": to_i64(identity.identity_revocation_epoch)?,
            ":previous_revocation": to_i64(
                binding.revocation.previous_identity_revocation_epoch
            )?,
            ":target": target.target_resource_id,
            ":provider": target.provider,
            ":previous_fence": to_i64(target.previous_fence)?,
            ":current_fence": to_i64(target.current_fence)?,
            ":version": to_i64(target.expected_resource_version)?,
            ":json": json,
            ":decision_json": decision_json,
            ":grant_json": grant_json,
            ":reserved_at": to_i64(reserved_at_epoch_s)?,
            ":issued_at": to_i64(command.issued_at_epoch_s)?,
            ":expires_at": to_i64(command.expires_at_epoch_s)?,
            ":previous_lifecycle_revocation": to_i64(
                target.previous_lifecycle_revocation_epoch
            )?,
            ":lifecycle_revocation": to_i64(target.lifecycle_revocation_epoch)?,
        },
    );
    match result {
        Ok(1) => Ok(digest),
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
