use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{
    CERTIFICATE_APPROVAL_EVIDENCE_SCHEMA_V2, CERTIFICATE_REVOCATION_EVIDENCE_SCHEMA_V2,
    CertificateActionV2, CertificateApprovalAssuranceV2, CertificateApprovalEvidenceV2,
    CertificateApprovalMethodV2, CertificateRevocationEvidenceV2, CertificateTargetBindingV2,
};

use crate::certificate_test_keys_v2::{
    APPROVAL_AUDIENCE, APPROVAL_ISSUER, NOW, REVOCATION_AUDIENCE, REVOCATION_ISSUER, SUBJECT,
    placeholder,
};

pub(crate) fn approval(
    action: CertificateActionV2,
    serial: u64,
    target: &CertificateTargetBindingV2,
) -> CertificateApprovalEvidenceV2 {
    CertificateApprovalEvidenceV2 {
        schema: CERTIFICATE_APPROVAL_EVIDENCE_SCHEMA_V2.into(),
        approval_id: format!("approval.certificate.{serial:04}"),
        challenge_id: format!("challenge.certificate.{serial:04}"),
        challenge_nonce_base64: URL_SAFE_NO_PAD.encode([u8::try_from(serial).unwrap(); 32]),
        issuer: APPROVAL_ISSUER.into(),
        audience: APPROVAL_AUDIENCE.into(),
        relying_party_id: "ihat.online".into(),
        origin: "https://ihat.online".into(),
        challenge_authority_ref: "authority.coela.local-presence".into(),
        approver_pairwise_subject: "subject.approver.security".into(),
        approver_actor: "actor.security.approver".into(),
        approver_profile: "profile.security.approver".into(),
        approver_device: "device.security.0001".into(),
        approver_proof_key_ref: "proof.key.security.0001".into(),
        action,
        target_resource_id: target.target_resource_id.clone(),
        request_digest_sha256: "10".repeat(32),
        credential_id: "credential.webauthn.0001".into(),
        ceremony_digest_sha256: "48".repeat(32),
        channel_binding_digest_sha256: "49".repeat(32),
        method: CertificateApprovalMethodV2::HardwareBackedUserPresence,
        assurance: CertificateApprovalAssuranceV2::Aal3,
        user_verified: true,
        phishing_resistant: true,
        authenticator_sign_count: serial,
        authenticator_backup_eligible: false,
        authenticator_backup_state: false,
        issued_at_epoch_s: NOW - 30,
        expires_at_epoch_s: NOW + 30,
        signed: placeholder("approval.certificate.key"),
    }
}

pub(crate) fn revocation(serial: u64) -> CertificateRevocationEvidenceV2 {
    CertificateRevocationEvidenceV2 {
        schema: CERTIFICATE_REVOCATION_EVIDENCE_SCHEMA_V2.into(),
        snapshot_id: format!("revocation.snapshot.{serial:04}"),
        issuer: REVOCATION_ISSUER.into(),
        audience: REVOCATION_AUDIENCE.into(),
        pairwise_subject: SUBJECT.into(),
        previous_identity_revocation_epoch: 8,
        identity_revocation_epoch: 9,
        verified_at_epoch_s: NOW - 20,
        authoritative: true,
        signed: placeholder("revocation.certificate.key"),
    }
}
