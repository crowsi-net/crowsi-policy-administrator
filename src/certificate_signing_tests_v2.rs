use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::CertificateActionV2;

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2, CertificateLeaseSignerOutcomeV2,
    CertificateLeaseSignerV2, CertificateSigningProgressV2, certificate_execution_v2,
    certificate_signing_store_v2,
    certificate_test_chain_v2::{administrator, chain, fence, pending},
    certificate_test_handoff_v2::accept_released,
    certificate_test_keys_v2::SUBJECT,
    certificate_test_signer_v2::TestSigner,
};

#[test]
fn definite_signer_failure_keeps_committed_state_and_allows_retry() {
    let fixture = chain(CertificateActionV2::Issue, 21, 0, None);
    let mut administrator = administrator();
    bootstrap(&mut administrator);
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    let progress = administrator
        .sign_certificate_execution_v2(
            &channel,
            &fixture.command.jti,
            &mut TestSigner::definitely_not_signed(),
        )
        .unwrap();
    assert!(matches!(
        progress,
        CertificateSigningProgressV2::DefinitelyNotSigned { .. }
    ));
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 0);
    assert_eq!(pending(&administrator), 1);
    administrator
        .sign_certificate_execution_v2(&channel, &fixture.command.jti, &mut TestSigner::signed())
        .unwrap();
    let authorization = administrator
        .release_signed_certificate_execution_v2(&channel, &fixture.command.jti)
        .unwrap();
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 0);
    accept_released(&mut administrator, &channel, &authorization);
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 1);
}

#[test]
fn ambiguous_signing_recovers_before_any_release_or_promotion() {
    let fixture = chain(CertificateActionV2::Issue, 22, 0, None);
    let mut administrator = administrator();
    bootstrap(&mut administrator);
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    let mut signer = TestSigner::unknown_then_signed();
    let progress = administrator
        .sign_certificate_execution_v2(&channel, &fixture.command.jti, &mut signer)
        .unwrap();
    assert!(matches!(
        progress,
        CertificateSigningProgressV2::OutcomeUnknown { .. }
    ));
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 0);
    let recovered = administrator
        .recover_certificate_execution_signature_v2(&channel, &fixture.command.jti, &mut signer)
        .unwrap();
    assert!(matches!(
        recovered,
        CertificateSigningProgressV2::Ready { .. }
    ));
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 0);
    let authorization = administrator
        .release_signed_certificate_execution_v2(&channel, &fixture.command.jti)
        .unwrap();
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 0);
    accept_released(&mut administrator, &channel, &authorization);
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 1);
}

#[test]
fn crash_after_sign_request_and_fabricated_signature_both_fail_closed() {
    let fixture = chain(CertificateActionV2::Issue, 23, 0, None);
    let mut administrator = administrator();
    bootstrap(&mut administrator);
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    let signer = TestSigner::signed();
    let prepared = certificate_execution_v2::prepare(
        &mut administrator,
        &fixture.command.jti,
        &signer.identity(),
    )
    .unwrap();
    assert!(matches!(
        certificate_signing_store_v2::store(
            &mut administrator,
            prepared,
            CertificateLeaseSignerOutcomeV2::Signed {
                signature_base64: URL_SAFE_NO_PAD.encode([0_u8; 64])
            }
        ),
        Err(AdministratorError::Signature)
    ));
    administrator
        .recover_certificate_execution_signature_v2(
            &channel,
            &fixture.command.jti,
            &mut TestSigner::signed(),
        )
        .unwrap();
    let authorization = administrator
        .release_signed_certificate_execution_v2(&channel, &fixture.command.jti)
        .unwrap();
    accept_released(&mut administrator, &channel, &authorization);
}

fn bootstrap(administrator: &mut crate::CertificatePolicyAdministratorV2) {
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
}
