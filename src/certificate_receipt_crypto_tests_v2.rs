use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::Signature;

use crate::{
    AdministratorError, ArtifactRole,
    certificate_receipt_crypto_fixture_v2::{authority_scope, fixture, manager_scope},
    certificate_test_keys_v2::policy,
};

#[test]
fn p256_receipts_require_canonical_raw_low_s_signatures() {
    let fixture = fixture();
    let keys = &fixture.administrator.trusted_keys;
    let policy = policy();
    assert!(
        keys.verify_certificate_receipt(
            ArtifactRole::CertificateAuthorityOutcomeEvidence,
            &authority_scope(),
            &policy.authority_receipt_key_purpose,
            &fixture.authority,
            &fixture.authority.signed,
        )
        .is_ok()
    );
    let raw = STANDARD
        .decode(&fixture.authority.signed.signature_base64)
        .unwrap();
    let low = Signature::from_slice(&raw).unwrap();
    let high = Signature::from_scalars(low.r().to_bytes(), (-low.s()).to_bytes()).unwrap();
    for malformed in [
        STANDARD.encode(high.to_bytes()),
        STANDARD.encode(low.to_der().as_bytes()),
        STANDARD.encode([0_u8; 63]),
        STANDARD.encode([0_u8; 65]),
        format!("{}=", fixture.authority.signed.signature_base64),
    ] {
        let mut signed = fixture.authority.signed.clone();
        signed.signature_base64 = malformed;
        assert!(matches!(
            keys.verify_certificate_receipt(
                ArtifactRole::CertificateAuthorityOutcomeEvidence,
                &authority_scope(),
                &policy.authority_receipt_key_purpose,
                &fixture.authority,
                &signed,
            ),
            Err(AdministratorError::Signature)
        ));
    }
}

#[test]
fn receipt_keys_are_exactly_role_scope_and_metadata_bound() {
    let fixture = fixture();
    let keys = &fixture.administrator.trusted_keys;
    let policy = policy();
    for mutate in [
        |value: &mut crowsi_control_contracts::CertificateReceiptSignatureV2| {
            value.key_id.push_str(".wrong");
        },
        |value: &mut crowsi_control_contracts::CertificateReceiptSignatureV2| {
            value.key_version.push_str(".wrong");
        },
        |value: &mut crowsi_control_contracts::CertificateReceiptSignatureV2| {
            value.public_key_spki_sha256 = "99".repeat(32);
        },
        |value: &mut crowsi_control_contracts::CertificateReceiptSignatureV2| {
            value.key_purpose.push_str(".wrong");
        },
    ] {
        let mut signed = fixture.authority.signed.clone();
        mutate(&mut signed);
        assert!(matches!(
            keys.verify_certificate_receipt(
                ArtifactRole::CertificateAuthorityOutcomeEvidence,
                &authority_scope(),
                &policy.authority_receipt_key_purpose,
                &fixture.authority,
                &signed,
            ),
            Err(AdministratorError::Trust)
        ));
    }
    assert!(matches!(
        keys.verify_certificate_receipt(
            ArtifactRole::CertificateManagerCommitEvidence,
            &manager_scope(),
            &policy.manager_commit_key_purpose,
            &fixture.authority,
            &fixture.authority.signed,
        ),
        Err(AdministratorError::Trust)
    ));
    assert!(matches!(
        keys.verify_certificate_receipt(
            ArtifactRole::CertificateManagerCommitEvidence,
            &manager_scope(),
            &policy.manager_commit_key_purpose,
            &fixture.manager,
            &fixture.authority.signed,
        ),
        Err(AdministratorError::Trust)
    ));
    let mut wrong_scope = authority_scope();
    if let crate::KeyScope::AuthorityOutcome {
        security_domain, ..
    } = &mut wrong_scope
    {
        *security_domain = "security.other".into();
    }
    assert!(matches!(
        keys.verify_certificate_receipt(
            ArtifactRole::CertificateAuthorityOutcomeEvidence,
            &wrong_scope,
            &policy.authority_receipt_key_purpose,
            &fixture.authority,
            &fixture.authority.signed,
        ),
        Err(AdministratorError::Trust)
    ));
}
