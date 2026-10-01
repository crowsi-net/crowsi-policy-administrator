use crowsi_control_contracts::{
    CertificateActionV2, CertificateExecutionDispositionV2, CertificateLifecycleActionV2,
    CertificatePayloadV2, SignedCertificateExecutionAuthorizationV2,
};

use crate::{
    certificate_test_chain_v2::ChainFixture,
    certificate_test_completion_model_v2::CompletionFixture,
    certificate_test_completion_v2::completion,
    certificate_test_keys_v2::{authority_outcome_signature, manager_commit_signature},
};

pub(crate) fn reconciliation_completion(
    chain: &ChainFixture,
    signed: &SignedCertificateExecutionAuthorizationV2,
    original: &ChainFixture,
    original_signed: &SignedCertificateExecutionAuthorizationV2,
    serial: u8,
    disposition: CertificateExecutionDispositionV2,
) -> CompletionFixture {
    let mut value = completion(chain, signed, serial, disposition);
    let target = &original.command.binding.target;
    value.authority.original_authorization_jti = Some(original.command.jti.clone());
    value.authority.original_operation_id = Some(original.command.operation_id.clone());
    value.authority.original_lease_digest_sha256 =
        Some(original_signed.lease_digest_sha256().into());
    value.authority.original_action = match original.command.action {
        CertificateActionV2::Issue => Some(CertificateLifecycleActionV2::Issue),
        CertificateActionV2::Renew => Some(CertificateLifecycleActionV2::Renew),
        CertificateActionV2::Revoke => Some(CertificateLifecycleActionV2::Revoke),
        _ => None,
    };
    value.authority.original_authority_command_digest_sha256 =
        Some(original.command.certificate_digest_sha256());
    value.authority.original_unknown_evidence_digest_sha256 = Some("42".repeat(32));
    value.authority.lifecycle_reservation_id = Some(original.command.pa_reservation_id.clone());
    value.authority.original_previous_fence = Some(target.previous_fence);
    value.authority.original_current_fence = Some(target.current_fence);
    value.authority.original_previous_lifecycle_revocation_epoch =
        Some(target.previous_lifecycle_revocation_epoch);
    value.authority.original_lifecycle_revocation_epoch = Some(target.lifecycle_revocation_epoch);
    value.authority.signed = authority_outcome_signature(&value.authority);
    value.manager.authority_evidence_digest_sha256 = value.authority.certificate_digest_sha256();
    value.manager.signed = manager_commit_signature(&value.manager);
    value
}
