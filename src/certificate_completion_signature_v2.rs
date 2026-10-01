use crate::{ArtifactRole, CertificateAdministratorPolicyV2, KeyScope, Result, TrustedKeys};

pub(crate) fn verify(
    policy: &CertificateAdministratorPolicyV2,
    keys: &TrustedKeys,
    authority: &crowsi_control_contracts::CertificateAuthorityOutcomeEvidenceV2,
    manager: &crowsi_control_contracts::CertificateManagerCommitEvidenceV2,
) -> Result<()> {
    keys.verify_certificate_receipt(
        ArtifactRole::CertificateAuthorityOutcomeEvidence,
        &KeyScope::AuthorityOutcome {
            issuer: policy.authority_outcome_issuer.clone(),
            audience: policy.authority_outcome_audience.clone(),
            authority_id: policy.certificate_authority_id.clone(),
            security_domain: policy.security_domain.clone(),
            deployment_id: policy.deployment_id.clone(),
        },
        &policy.authority_receipt_key_purpose,
        authority,
        &authority.signed,
    )?;
    keys.verify_certificate_receipt(
        ArtifactRole::CertificateManagerCommitEvidence,
        &KeyScope::ManagerCommit {
            issuer: policy.manager_commit_issuer.clone(),
            audience: policy.manager_commit_audience.clone(),
            workload: policy.manager_commit_workload.clone(),
            security_domain: policy.security_domain.clone(),
            deployment_id: policy.deployment_id.clone(),
        },
        &policy.manager_commit_key_purpose,
        manager,
        &manager.signed,
    )
}
