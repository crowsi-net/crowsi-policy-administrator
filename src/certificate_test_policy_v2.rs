use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::CertificateSignatureAlgorithmV2;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use sha2::{Digest, Sha256};

use crate::{
    CertificateAdministratorPolicyV2, certificate_test_key_material_v2::spki_digest,
    certificate_test_keys_v2::*,
};

pub(crate) fn policy() -> CertificateAdministratorPolicyV2 {
    let signer_key = Ed25519SigningKey::from_bytes(&[LEASE_SIGNER_SEED; 32])
        .verifying_key()
        .to_bytes();
    let mut signer_spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    signer_spki.extend_from_slice(&signer_key);
    CertificateAdministratorPolicyV2 {
        security_domain: "security.crowsi".into(),
        deployment_id: "deployment.local".into(),
        authorization_issuer: "https://ihat.online/pa".into(),
        authorization_audience: "service://crowsi/certificate-manager".into(),
        authorization_provider: "provider.policy.administrator".into(),
        authorization_policy_id: POLICY_ID.into(),
        authorization_policy_digest_sha256: "20".repeat(32),
        authorization_verifier_key_id: "key.policy.administrator".into(),
        authorization_signer_key_version: "version.0001".into(),
        authorization_signer_public_key_base64: URL_SAFE_NO_PAD.encode(signer_key),
        authorization_signer_public_key_digest_sha256: format!("{:x}", Sha256::digest(signer_key)),
        authorization_signer_public_key_spki_sha256: format!("{:x}", Sha256::digest(signer_spki)),
        authorization_signer_workload: "spiffe://crowsi.test/pa/lease-signer".into(),
        authorization_signer_purpose: "certificate-execution-authorization".into(),
        authorization_signature_algorithm: CertificateSignatureAlgorithmV2::Ed25519,
        authorization_channel: "channel.service.automation".into(),
        target_resource_normalizer_id: "normalizer.certificate.target".into(),
        target_resource_normalizer_version: "version.0001".into(),
        approval_issuer: APPROVAL_ISSUER.into(),
        approval_audience: APPROVAL_AUDIENCE.into(),
        approval_relying_party_id: "ihat.online".into(),
        approval_origin: "https://ihat.online".into(),
        approval_challenge_authority_ref: "authority.coela.local-presence".into(),
        authority_outcome_issuer: OUTCOME_ISSUER.into(),
        authority_outcome_audience: OUTCOME_AUDIENCE.into(),
        certificate_authority_id: "authority.crowsi.local".into(),
        authority_receipt_key_id: AUTHORITY_RECEIPT_KEY.0.into(),
        authority_receipt_key_version: "version.0001".into(),
        authority_receipt_public_key_spki_sha256: spki_digest(AUTHORITY_RECEIPT_KEY.1),
        authority_receipt_key_purpose: "certificate-authority-receipt".into(),
        manager_commit_issuer: COMMIT_ISSUER.into(),
        manager_commit_audience: COMMIT_AUDIENCE.into(),
        manager_commit_workload: "spiffe://crowsi.test/certificate-manager".into(),
        manager_commit_key_id: MANAGER_COMMIT_KEY.0.into(),
        manager_commit_key_version: "version.0001".into(),
        manager_commit_public_key_spki_sha256: spki_digest(MANAGER_COMMIT_KEY.1),
        manager_commit_key_purpose: "certificate-manager-commit-receipt".into(),
        manager_handoff_issuer: HANDOFF_ISSUER.into(),
        manager_handoff_audience: HANDOFF_AUDIENCE.into(),
        manager_handoff_workload: "spiffe://crowsi.test/certificate-manager".into(),
        manager_handoff_key_id: MANAGER_HANDOFF_KEY.0.into(),
        manager_handoff_key_version: "version.0001".into(),
        manager_handoff_public_key_spki_sha256: spki_digest(MANAGER_HANDOFF_KEY.1),
        manager_handoff_key_purpose: "certificate-manager-handoff-receipt".into(),
        revocation_issuer: REVOCATION_ISSUER.into(),
        revocation_audience: REVOCATION_AUDIENCE.into(),
        trust_revision: 7,
        max_authorization_ttl_seconds: 120,
        max_revocation_snapshot_age_seconds: 60,
        max_completion_recovery_seconds: 86_400,
    }
}
