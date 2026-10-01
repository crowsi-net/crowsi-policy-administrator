use crowsi_control_contracts::{CertificatePayloadV2, Validate};

use crate::{
    AdministratorError, ArtifactRole, CertificatePolicyAdministratorV2,
    CertificateReservationInputV2, KeyScope, Result,
};

pub(crate) fn verify(
    administrator: &CertificatePolicyAdministratorV2,
    input: &CertificateReservationInputV2<'_>,
    now_epoch_s: u64,
) -> Result<()> {
    let Some(evidence) = input.approval_evidence else {
        return if input.command.action.requires_separation_of_duties() {
            Err(AdministratorError::Binding)
        } else {
            Ok(())
        };
    };
    if !input.command.action.requires_separation_of_duties() {
        return Err(AdministratorError::Binding);
    }
    evidence
        .validate()
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    let command = input.command;
    let binding = &command.binding;
    let policy = &administrator.policy;
    let exact = evidence.issuer == policy.approval_issuer
        && evidence.audience == policy.approval_audience
        && evidence.relying_party_id == policy.approval_relying_party_id
        && evidence.origin == policy.approval_origin
        && evidence.challenge_authority_ref == policy.approval_challenge_authority_ref
        && binding.approval_id.as_deref() == Some(evidence.approval_id.as_str())
        && binding.approval_evidence_digest_sha256.as_deref()
            == Some(evidence.certificate_digest_sha256().as_str())
        && binding.approval_method == Some(evidence.method)
        && binding.approval_assurance == Some(evidence.assurance)
        && binding.approval_issued_at_epoch_s == Some(evidence.issued_at_epoch_s)
        && binding.approval_expires_at_epoch_s == Some(evidence.expires_at_epoch_s)
        && binding.approval_verified_at_epoch_s == Some(evidence.issued_at_epoch_s)
        && binding.identity.approver_pairwise_subject.as_deref()
            == Some(evidence.approver_pairwise_subject.as_str())
        && binding.identity.approver_actor.as_deref() == Some(evidence.approver_actor.as_str())
        && binding.identity.approver_profile.as_deref() == Some(evidence.approver_profile.as_str())
        && binding.identity.approver_device.as_deref() == Some(evidence.approver_device.as_str())
        && binding.identity.approver_proof_key_ref.as_deref()
            == Some(evidence.approver_proof_key_ref.as_str())
        && evidence.action == command.action
        && evidence.target_resource_id == binding.target.target_resource_id
        && evidence.request_digest_sha256 == command.request_digest_sha256
        && command.issued_at_epoch_s >= evidence.issued_at_epoch_s
        && command.expires_at_epoch_s <= evidence.expires_at_epoch_s
        && evidence.issued_at_epoch_s <= now_epoch_s
        && now_epoch_s < evidence.expires_at_epoch_s
        && evidence.signed.key_id != input.decision.signed.key_id
        && evidence.signed.key_id != input.grant.signed.key_id;
    if !exact {
        return Err(AdministratorError::Binding);
    }
    administrator.trusted_keys.verify_certificate(
        ArtifactRole::CertificateApprovalEvidence,
        &KeyScope::Approval {
            issuer: evidence.issuer.clone(),
            audience: evidence.audience.clone(),
        },
        evidence,
        &evidence.signed,
    )
}
