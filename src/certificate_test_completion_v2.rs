use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{
    CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2,
    CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2, CertificateActionV2,
    CertificateAuthorityOutcomeEvidenceV2, CertificateExecutionDispositionV2,
    CertificateManagerCommitEvidenceV2, CertificatePayloadV2,
    CertificateReceiptSignatureAlgorithmV2, SignedCertificateExecutionAuthorizationV2,
};

use crate::{
    certificate_test_chain_v2::ChainFixture,
    certificate_test_completion_model_v2::placeholder_receipt,
    certificate_test_keys_v2::{
        COMMIT_AUDIENCE, COMMIT_ISSUER, NOW, OUTCOME_AUDIENCE, OUTCOME_ISSUER,
        authority_outcome_signature, manager_commit_signature, policy,
    },
};

pub(crate) use crate::certificate_test_completion_model_v2::CompletionFixture;
pub(crate) use crate::certificate_test_reconciliation_v2::reconciliation_completion;

#[allow(clippy::too_many_lines)]
pub(crate) fn completion(
    chain: &ChainFixture,
    signed: &SignedCertificateExecutionAuthorizationV2,
    serial: u8,
    disposition: CertificateExecutionDispositionV2,
) -> CompletionFixture {
    let policy = policy();
    let command = &chain.command;
    let target = &command.binding.target;
    let mut authority = CertificateAuthorityOutcomeEvidenceV2 {
        schema: CERTIFICATE_AUTHORITY_OUTCOME_EVIDENCE_SCHEMA_V2.into(),
        evidence_id: format!("authority.evidence.{serial:04}"),
        nonce_base64: URL_SAFE_NO_PAD.encode([serial; 32]),
        issuer: OUTCOME_ISSUER.into(),
        audience: OUTCOME_AUDIENCE.into(),
        action: command.action,
        authorization_jti: command.jti.clone(),
        operation_id: command.operation_id.clone(),
        lease_digest_sha256: signed.lease_digest_sha256().into(),
        authorization_command_digest_sha256: command.certificate_digest_sha256(),
        target_resource_id: target.target_resource_id.clone(),
        expected_resource_version: target.expected_resource_version,
        previous_fence: target.previous_fence,
        current_fence: target.current_fence,
        previous_lifecycle_revocation_epoch: target.previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: target.lifecycle_revocation_epoch,
        disposition,
        authority_outcome_digest_sha256: (disposition
            == CertificateExecutionDispositionV2::Completed)
            .then(|| "51".repeat(32)),
        original_authorization_jti: None,
        original_operation_id: None,
        original_lease_digest_sha256: None,
        original_action: None,
        original_authority_command_digest_sha256: None,
        original_unknown_evidence_digest_sha256: None,
        lifecycle_reservation_id: None,
        original_previous_fence: None,
        original_current_fence: None,
        original_previous_lifecycle_revocation_epoch: None,
        original_lifecycle_revocation_epoch: None,
        security_domain: command.binding.deployment.security_domain.clone(),
        deployment_id: command.binding.deployment.deployment_id.clone(),
        trust_revision: command.binding.deployment.trust_revision,
        authority_id: policy.certificate_authority_id,
        receipt_key_id: policy.authority_receipt_key_id.clone(),
        receipt_key_version: policy.authority_receipt_key_version.clone(),
        receipt_public_key_spki_sha256: policy.authority_receipt_public_key_spki_sha256.clone(),
        receipt_signature_algorithm:
            CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        receipt_key_purpose: policy.authority_receipt_key_purpose.clone(),
        issued_at_epoch_s: NOW - 4,
        expires_at_epoch_s: NOW + 30,
        signed: placeholder_receipt(
            &policy.authority_receipt_key_id,
            &policy.authority_receipt_key_version,
            &policy.authority_receipt_public_key_spki_sha256,
            &policy.authority_receipt_key_purpose,
        ),
    };
    authority.signed = authority_outcome_signature(&authority);
    let changed = disposition == CertificateExecutionDispositionV2::Completed
        && matches!(
            command.action,
            CertificateActionV2::Issue
                | CertificateActionV2::Renew
                | CertificateActionV2::Revoke
                | CertificateActionV2::ReconcileUnknown
        );
    let mut manager = CertificateManagerCommitEvidenceV2 {
        schema: CERTIFICATE_MANAGER_COMMIT_EVIDENCE_SCHEMA_V2.into(),
        commit_id: format!("manager.commit.{serial:04}"),
        nonce_base64: URL_SAFE_NO_PAD.encode([serial.wrapping_add(128); 32]),
        issuer: COMMIT_ISSUER.into(),
        audience: COMMIT_AUDIENCE.into(),
        action: command.action,
        authorization_jti: command.jti.clone(),
        operation_id: command.operation_id.clone(),
        lease_digest_sha256: signed.lease_digest_sha256().into(),
        authorization_command_digest_sha256: command.certificate_digest_sha256(),
        target_resource_id: target.target_resource_id.clone(),
        state_revision: u64::from(serial) + 1,
        resource_version: target.expected_resource_version + u64::from(changed),
        previous_fence: target.previous_fence,
        current_fence: target.current_fence,
        previous_lifecycle_revocation_epoch: target.previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: target.lifecycle_revocation_epoch,
        disposition,
        authority_evidence_id: authority.evidence_id.clone(),
        authority_evidence_digest_sha256: authority.certificate_digest_sha256(),
        security_domain: command.binding.deployment.security_domain.clone(),
        deployment_id: command.binding.deployment.deployment_id.clone(),
        trust_revision: command.binding.deployment.trust_revision,
        manager_workload: policy.manager_commit_workload,
        commit_key_id: policy.manager_commit_key_id.clone(),
        commit_key_version: policy.manager_commit_key_version.clone(),
        commit_public_key_spki_sha256: policy.manager_commit_public_key_spki_sha256.clone(),
        commit_signature_algorithm:
            CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        commit_key_purpose: policy.manager_commit_key_purpose.clone(),
        committed_at_epoch_s: NOW - 2,
        evidence_issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 20,
        submission_recovery_deadline_epoch_s: NOW + 86_398,
        signed: placeholder_receipt(
            &policy.manager_commit_key_id,
            &policy.manager_commit_key_version,
            &policy.manager_commit_public_key_spki_sha256,
            &policy.manager_commit_key_purpose,
        ),
    };
    manager.signed = manager_commit_signature(&manager);
    CompletionFixture { authority, manager }
}
