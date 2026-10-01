use crowsi_control_contracts::{CertificateManagerHandoffDispositionV2, CertificatePayloadV2};

use crate::{
    AdministratorError, ArtifactRole, CertificateHandoffInputV2, KeyScope, Result,
    certificate_handoff_load_v2,
};

pub(crate) fn verify(
    policy: &crate::CertificateAdministratorPolicyV2,
    trusted_keys: &crate::TrustedKeys,
    pending: &certificate_handoff_load_v2::PendingHandoff,
    input: &CertificateHandoffInputV2<'_>,
    now: u64,
) -> Result<()> {
    let evidence = input.evidence;
    let command = &pending.lease.command;
    let target = &command.binding.target;
    let deployment = &command.binding.deployment;
    let exact = evidence.issuer == policy.manager_handoff_issuer
        && evidence.audience == policy.manager_handoff_audience
        && evidence.manager_workload == policy.manager_handoff_workload
        && evidence.receipt_key_id == policy.manager_handoff_key_id
        && evidence.receipt_key_version == policy.manager_handoff_key_version
        && evidence.receipt_public_key_spki_sha256 == policy.manager_handoff_public_key_spki_sha256
        && evidence.receipt_key_purpose == policy.manager_handoff_key_purpose
        && evidence.security_domain == policy.security_domain
        && evidence.deployment_id == policy.deployment_id
        && evidence.trust_revision == policy.trust_revision
        && evidence.action == command.action
        && evidence.authorization_jti == command.jti
        && evidence.operation_id == command.operation_id
        && evidence.lease_digest_sha256 == pending.lease_digest_sha256
        && evidence.authorization_command_digest_sha256 == command.certificate_digest_sha256()
        && evidence.target_resource_id == target.target_resource_id
        && evidence.expected_resource_version == target.expected_resource_version
        && evidence.previous_fence == target.previous_fence
        && evidence.current_fence == target.current_fence
        && evidence.previous_lifecycle_revocation_epoch
            == target.previous_lifecycle_revocation_epoch
        && evidence.lifecycle_revocation_epoch == target.lifecycle_revocation_epoch
        && deployment.security_domain == evidence.security_domain
        && deployment.deployment_id == evidence.deployment_id;
    if !exact {
        return Err(AdministratorError::Binding);
    }
    if evidence.observed_at_epoch_s > now || now >= evidence.expires_at_epoch_s {
        return Err(AdministratorError::Time);
    }
    verify_disposition(evidence, pending.command_expires_at_epoch_s, now)?;
    trusted_keys.verify_certificate_receipt(
        ArtifactRole::CertificateManagerHandoffEvidence,
        &KeyScope::ManagerHandoff {
            issuer: policy.manager_handoff_issuer.clone(),
            audience: policy.manager_handoff_audience.clone(),
            workload: policy.manager_handoff_workload.clone(),
            security_domain: policy.security_domain.clone(),
            deployment_id: policy.deployment_id.clone(),
        },
        &policy.manager_handoff_key_purpose,
        evidence,
        &evidence.signed,
    )
}

fn verify_disposition(
    evidence: &crowsi_control_contracts::CertificateManagerHandoffEvidenceV2,
    command_expiry: u64,
    now: u64,
) -> Result<()> {
    let valid = match evidence.disposition {
        CertificateManagerHandoffDispositionV2::Accepted => {
            evidence.observed_at_epoch_s < command_expiry && now < command_expiry
        }
        CertificateManagerHandoffDispositionV2::NotAccepted => {
            evidence.observed_at_epoch_s >= command_expiry && now >= command_expiry
        }
    };
    valid.then_some(()).ok_or(AdministratorError::Time)
}
