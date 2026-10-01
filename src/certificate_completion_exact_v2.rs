use crowsi_control_contracts::{
    CertificateExecutionCommandV2, CertificateExecutionDispositionV2, CertificatePayloadV2,
};

use crate::{
    CertificateAdministratorPolicyV2, certificate_completion_load_v2::CompletionReservation,
};

pub(crate) fn stored(
    policy: &CertificateAdministratorPolicyV2,
    row: &CompletionReservation,
    command: &CertificateExecutionCommandV2,
) -> bool {
    command.certificate_digest_sha256() == row.command_digest_sha256
        && command.jti == row.authorization_jti
        && command.action.as_str() == row.action
        && command.operation_id == row.operation_id
        && command.binding.target.target_resource_id == row.target_resource_id
        && command.binding.target.expected_resource_version == row.expected_resource_version
        && command.binding.target.previous_fence == row.previous_fence
        && command.binding.target.current_fence == row.current_fence
        && command.binding.target.previous_lifecycle_revocation_epoch
            == row.previous_lifecycle_epoch
        && command.binding.target.lifecycle_revocation_epoch == row.lifecycle_epoch
        && command.binding.deployment.security_domain == row.security_domain
        && command.binding.deployment.deployment_id == row.deployment_id
        && command.binding.target.provider == row.provider
        && command.binding.target.service_id == row.service_id
        && command.binding.identity.workload == row.workload
        && command.binding.identity.pairwise_subject == row.pairwise_subject
        && command.binding.identity.requester_profile == row.profile
        && command.binding.deployment.trust_revision == policy.trust_revision
}

pub(crate) fn current(
    policy: &CertificateAdministratorPolicyV2,
    row: &CompletionReservation,
    command: &CertificateExecutionCommandV2,
    authority: &crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
    manager: &crowsi_control_contracts::CertificateManagerCommitEvidenceV2,
    now: u64,
) -> bool {
    let common = authority.action.as_str() == row.action
        && authority.authorization_jti == command.jti
        && authority.operation_id == row.operation_id
        && authority.lease_digest_sha256 == row.lease_digest_sha256
        && authority.authorization_command_digest_sha256 == row.command_digest_sha256
        && authority.target_resource_id == row.target_resource_id
        && authority.expected_resource_version == row.expected_resource_version
        && authority.previous_fence == row.previous_fence
        && authority.current_fence == row.current_fence
        && authority.previous_lifecycle_revocation_epoch == row.previous_lifecycle_epoch
        && authority.lifecycle_revocation_epoch == row.lifecycle_epoch
        && authority.security_domain == row.security_domain
        && authority.deployment_id == row.deployment_id
        && authority.trust_revision == command.binding.deployment.trust_revision
        && authority.issued_at_epoch_s <= manager.committed_at_epoch_s;
    common
        && authority_policy_exact(policy, authority)
        && manager_exact(policy, row, authority, manager, now)
        && valid_resource_version(row, authority.disposition, manager.resource_version)
}

fn manager_exact(
    policy: &CertificateAdministratorPolicyV2,
    row: &CompletionReservation,
    authority: &crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
    manager: &crowsi_control_contracts::CertificateManagerCommitEvidenceV2,
    now: u64,
) -> bool {
    manager.issuer == policy.manager_commit_issuer
        && manager.audience == policy.manager_commit_audience
        && manager.manager_workload == policy.manager_commit_workload
        && manager.commit_key_id == policy.manager_commit_key_id
        && manager.commit_key_version == policy.manager_commit_key_version
        && manager.commit_public_key_spki_sha256 == policy.manager_commit_public_key_spki_sha256
        && manager.commit_key_purpose == policy.manager_commit_key_purpose
        && manager.security_domain == policy.security_domain
        && manager.deployment_id == policy.deployment_id
        && manager.trust_revision == policy.trust_revision
        && manager.action.as_str() == row.action
        && manager.authorization_jti == authority.authorization_jti
        && manager.operation_id == row.operation_id
        && manager.lease_digest_sha256 == row.lease_digest_sha256
        && manager.authorization_command_digest_sha256 == row.command_digest_sha256
        && manager.target_resource_id == row.target_resource_id
        && manager.previous_fence == row.previous_fence
        && manager.current_fence == row.current_fence
        && manager.previous_lifecycle_revocation_epoch == row.previous_lifecycle_epoch
        && manager.lifecycle_revocation_epoch == row.lifecycle_epoch
        && manager.disposition == authority.disposition
        && manager.authority_evidence_id == authority.evidence_id
        && manager.authority_evidence_digest_sha256 == authority.certificate_digest_sha256()
        && authority.issued_at_epoch_s <= manager.committed_at_epoch_s
        && manager.committed_at_epoch_s < authority.expires_at_epoch_s
        && manager.committed_at_epoch_s <= manager.evidence_issued_at_epoch_s
        && manager.evidence_issued_at_epoch_s < manager.expires_at_epoch_s
        && manager.evidence_issued_at_epoch_s <= now
        && manager.committed_at_epoch_s <= now
        && now <= manager.submission_recovery_deadline_epoch_s
        && manager
            .committed_at_epoch_s
            .checked_add(policy.max_completion_recovery_seconds)
            .is_some_and(|maximum| manager.submission_recovery_deadline_epoch_s <= maximum)
}

fn authority_policy_exact(
    policy: &CertificateAdministratorPolicyV2,
    value: &crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
) -> bool {
    value.issuer == policy.authority_outcome_issuer
        && value.audience == policy.authority_outcome_audience
        && value.authority_id == policy.certificate_authority_id
        && value.receipt_key_id == policy.authority_receipt_key_id
        && value.receipt_key_version == policy.authority_receipt_key_version
        && value.receipt_public_key_spki_sha256 == policy.authority_receipt_public_key_spki_sha256
        && value.receipt_key_purpose == policy.authority_receipt_key_purpose
        && value.security_domain == policy.security_domain
        && value.deployment_id == policy.deployment_id
        && value.trust_revision == policy.trust_revision
}

fn valid_resource_version(
    row: &CompletionReservation,
    disposition: CertificateExecutionDispositionV2,
    actual: u64,
) -> bool {
    let changed = disposition == CertificateExecutionDispositionV2::Completed
        && matches!(
            row.action.as_str(),
            "issue" | "renew" | "revoke" | "reconcile-unknown"
        );
    row.expected_resource_version
        .checked_add(u64::from(changed))
        == Some(actual)
}
