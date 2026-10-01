use crowsi_control_contracts::{
    CertificateActionV2, CertificateAuthorityOutcomeEvidenceV2, CertificateExecutionDispositionV2,
    CertificateManagerCommitEvidenceV2,
};

use crate::{
    AuthenticatedCertificateManagerChannelV2, CertificatePolicyAdministratorV2, KeyScope,
    certificate_test_chain_v2::{administrator, chain},
    certificate_test_completion_v2::completion,
    certificate_test_keys_v2::{SUBJECT, policy},
    certificate_test_signer_v2::sign_and_release,
};

pub(crate) struct ReceiptCryptoFixture {
    pub(crate) administrator: CertificatePolicyAdministratorV2,
    pub(crate) authority: CertificateAuthorityOutcomeEvidenceV2,
    pub(crate) manager: CertificateManagerCommitEvidenceV2,
}

pub(crate) fn fixture() -> ReceiptCryptoFixture {
    let chain = chain(CertificateActionV2::Issue, 91, 0, None);
    let mut administrator = administrator();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    administrator
        .reserve_certificate_execution_v2(&chain.input())
        .unwrap();
    let signed = sign_and_release(&mut administrator, &channel, &chain.command.jti);
    let completion = completion(
        &chain,
        &signed,
        91,
        CertificateExecutionDispositionV2::Completed,
    );
    ReceiptCryptoFixture {
        administrator,
        authority: completion.authority,
        manager: completion.manager,
    }
}

pub(crate) fn authority_scope() -> KeyScope {
    let policy = policy();
    KeyScope::AuthorityOutcome {
        issuer: policy.authority_outcome_issuer,
        audience: policy.authority_outcome_audience,
        authority_id: policy.certificate_authority_id,
        security_domain: policy.security_domain,
        deployment_id: policy.deployment_id,
    }
}

pub(crate) fn manager_scope() -> KeyScope {
    let policy = policy();
    KeyScope::ManagerCommit {
        issuer: policy.manager_commit_issuer,
        audience: policy.manager_commit_audience,
        workload: policy.manager_commit_workload,
        security_domain: policy.security_domain,
        deployment_id: policy.deployment_id,
    }
}
