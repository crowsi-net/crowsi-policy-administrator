use crowsi_control_contracts::{
    CertificateAuthorityOutcomeEvidenceV2, CertificateExecutionCommandV2,
    CertificateOperationBindingV2, CertificatePayloadV2, Validate,
};
use rusqlite::Transaction;

use crate::{
    AdministratorError, Result,
    certificate_completion_load_v2::{CompletionReservation, original},
};

pub(crate) fn verify(
    tx: &Transaction<'_>,
    reservation: &CompletionReservation,
    command: &CertificateExecutionCommandV2,
    evidence: &CertificateAuthorityOutcomeEvidenceV2,
) -> Result<()> {
    if command.action != crowsi_control_contracts::CertificateActionV2::ReconcileUnknown {
        return Ok(());
    }
    let related = reservation
        .related_authorization_jti
        .as_deref()
        .ok_or(AdministratorError::Binding)?;
    let Some(CertificateOperationBindingV2::ReconcileUnknown {
        original_action,
        target_operation_id,
        lifecycle_reservation_id,
        authority_command_digest_sha256,
        unknown_evidence_digest_sha256,
        locked_previous_fence,
        locked_current_fence,
        locked_previous_lifecycle_revocation_epoch,
        locked_lifecycle_revocation_epoch,
    }) = command.binding.operation.as_ref()
    else {
        return Err(AdministratorError::Binding);
    };
    let original = original(tx, related)?;
    let stored: CertificateExecutionCommandV2 = serde_json::from_str(&original.command_json)
        .map_err(|_| AdministratorError::LedgerIntegrity)?;
    stored
        .validate()
        .map_err(|_| AdministratorError::LedgerIntegrity)?;
    let stored_exact = stored.certificate_digest_sha256() == original.command_digest_sha256
        && stored.jti == original.authorization_jti
        && stored.operation_id == original.operation_id
        && stored.action.as_str() == original.action
        && stored.pa_reservation_id == original.pa_reservation_id
        && stored.binding.target.previous_fence == original.previous_fence
        && stored.binding.target.current_fence == original.current_fence
        && stored.binding.target.previous_lifecycle_revocation_epoch
            == original.previous_lifecycle_epoch
        && stored.binding.target.lifecycle_revocation_epoch == original.lifecycle_epoch
        && stored.binding.deployment.security_domain == original.security_domain
        && stored.binding.deployment.deployment_id == original.deployment_id
        && stored.binding.target.provider == original.provider
        && stored.binding.target.target_resource_id == original.target_resource_id
        && stored.binding.target.expected_resource_version == original.expected_resource_version
        && stored.binding.target.service_id == original.service_id
        && stored.binding.identity.workload == original.workload
        && stored.binding.identity.pairwise_subject == original.pairwise_subject
        && stored.binding.identity.requester_profile == original.profile;
    let immutable_boundary = command.binding.deployment.security_domain
        == stored.binding.deployment.security_domain
        && command.binding.deployment.deployment_id == stored.binding.deployment.deployment_id
        && command.binding.deployment.trust_revision == stored.binding.deployment.trust_revision
        && command.binding.target.provider == stored.binding.target.provider
        && command.binding.target.target_resource_id == stored.binding.target.target_resource_id
        && command.binding.target.service_id == stored.binding.target.service_id
        && command.binding.identity.workload == stored.binding.identity.workload
        && command.binding.identity.pairwise_subject == stored.binding.identity.pairwise_subject
        && command.binding.identity.requester_pairwise_subject
            == stored.binding.identity.requester_pairwise_subject
        && command.binding.identity.requester_profile == stored.binding.identity.requester_profile;
    let exact = stored_exact
        && immutable_boundary
        && related == original.authorization_jti
        && evidence.original_authorization_jti.as_deref() == Some(related)
        && evidence.original_operation_id == Some(original.operation_id.clone())
        && evidence.original_lease_digest_sha256 == Some(original.lease_digest_sha256.clone())
        && evidence.original_action == Some(*original_action)
        && evidence.original_authority_command_digest_sha256
            == Some(original.command_digest_sha256.clone())
        && evidence.original_unknown_evidence_digest_sha256
            == Some(original.unknown_evidence_digest_sha256.clone())
        && evidence.lifecycle_reservation_id == Some(original.pa_reservation_id.clone())
        && evidence.original_previous_fence == Some(original.previous_fence)
        && evidence.original_current_fence == Some(original.current_fence)
        && evidence.original_previous_lifecycle_revocation_epoch
            == Some(original.previous_lifecycle_epoch)
        && evidence.original_lifecycle_revocation_epoch == Some(original.lifecycle_epoch)
        && target_operation_id == &original.operation_id
        && original_action.as_str() == original.action
        && lifecycle_reservation_id == &original.pa_reservation_id
        && authority_command_digest_sha256 == &original.command_digest_sha256
        && unknown_evidence_digest_sha256 == &original.unknown_evidence_digest_sha256
        && locked_previous_fence == &original.previous_fence
        && locked_current_fence == &original.current_fence
        && locked_previous_lifecycle_revocation_epoch == &original.previous_lifecycle_epoch
        && locked_lifecycle_revocation_epoch == &original.lifecycle_epoch;
    exact.then_some(()).ok_or(AdministratorError::Binding)
}
