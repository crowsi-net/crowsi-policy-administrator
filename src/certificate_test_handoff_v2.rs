use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use crowsi_control_contracts::{
    CERTIFICATE_MANAGER_HANDOFF_EVIDENCE_SCHEMA_V2, CertificateExecutionLeaseV2,
    CertificateManagerHandoffDispositionV2, CertificateManagerHandoffEvidenceV2,
    CertificatePayloadV2, CertificateReceiptSignatureAlgorithmV2, CertificateReceiptSignatureV2,
    SignedCertificateExecutionAuthorizationV2,
};
use sha2::{Digest, Sha256};

use crate::certificate_test_keys_v2::{
    HANDOFF_AUDIENCE, HANDOFF_ISSUER, NOW, manager_handoff_signature, policy,
};
use crate::{
    AuthenticatedCertificateManagerChannelV2, CertificateHandoffInputV2,
    CertificatePolicyAdministratorV2,
};

pub(crate) fn evidence(
    signed: &SignedCertificateExecutionAuthorizationV2,
    disposition: CertificateManagerHandoffDispositionV2,
    observed_at_epoch_s: u64,
) -> CertificateManagerHandoffEvidenceV2 {
    let bytes = STANDARD.decode(signed.pa_pep_lease_base64()).unwrap();
    let lease: CertificateExecutionLeaseV2 = serde_json::from_slice(&bytes).unwrap();
    let command = &lease.command;
    let target = &command.binding.target;
    let policy = policy();
    let nonce = Sha256::digest(command.jti.as_bytes());
    let mut value = CertificateManagerHandoffEvidenceV2 {
        schema: CERTIFICATE_MANAGER_HANDOFF_EVIDENCE_SCHEMA_V2.into(),
        receipt_id: format!("handoff.receipt.{}", command.authorization_id),
        nonce_base64: URL_SAFE_NO_PAD.encode(nonce),
        issuer: HANDOFF_ISSUER.into(),
        audience: HANDOFF_AUDIENCE.into(),
        disposition,
        action: command.action,
        authorization_jti: command.jti.clone(),
        operation_id: command.operation_id.clone(),
        lease_digest_sha256: lease.certificate_digest_sha256(),
        authorization_command_digest_sha256: command.certificate_digest_sha256(),
        security_domain: command.binding.deployment.security_domain.clone(),
        deployment_id: command.binding.deployment.deployment_id.clone(),
        trust_revision: command.binding.deployment.trust_revision,
        target_resource_id: target.target_resource_id.clone(),
        expected_resource_version: target.expected_resource_version,
        previous_fence: target.previous_fence,
        current_fence: target.current_fence,
        previous_lifecycle_revocation_epoch: target.previous_lifecycle_revocation_epoch,
        lifecycle_revocation_epoch: target.lifecycle_revocation_epoch,
        manager_workload: policy.manager_handoff_workload,
        receipt_key_id: policy.manager_handoff_key_id.clone(),
        receipt_key_version: policy.manager_handoff_key_version.clone(),
        receipt_public_key_spki_sha256: policy.manager_handoff_public_key_spki_sha256.clone(),
        receipt_signature_algorithm:
            CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        receipt_key_purpose: policy.manager_handoff_key_purpose.clone(),
        observed_at_epoch_s,
        expires_at_epoch_s: observed_at_epoch_s + 30,
        signed: placeholder(
            &policy.manager_handoff_key_id,
            &policy.manager_handoff_key_version,
            &policy.manager_handoff_public_key_spki_sha256,
            &policy.manager_handoff_key_purpose,
        ),
    };
    value.signed = manager_handoff_signature(&value);
    value
}

pub(crate) fn accepted(
    signed: &SignedCertificateExecutionAuthorizationV2,
) -> CertificateManagerHandoffEvidenceV2 {
    evidence(
        signed,
        CertificateManagerHandoffDispositionV2::Accepted,
        NOW,
    )
}

pub(crate) fn accept_released(
    administrator: &mut CertificatePolicyAdministratorV2,
    channel: &AuthenticatedCertificateManagerChannelV2,
    signed: &SignedCertificateExecutionAuthorizationV2,
) {
    administrator
        .accept_released_certificate_execution_v2(
            channel,
            &CertificateHandoffInputV2 {
                evidence: &accepted(signed),
            },
        )
        .unwrap();
}

fn placeholder(
    key: &str,
    version: &str,
    spki: &str,
    purpose: &str,
) -> CertificateReceiptSignatureV2 {
    CertificateReceiptSignatureV2 {
        key_id: key.into(),
        key_version: version.into(),
        public_key_spki_sha256: spki.into(),
        key_purpose: purpose.into(),
        algorithm: CertificateReceiptSignatureAlgorithmV2::EcdsaP256Sha256P1363LowS,
        digest_sha256: "00".repeat(32),
        signature_base64: STANDARD.encode([0_u8; 64]),
    }
}
