use crowsi_control_contracts::CertificateActionV2;
use crowsi_control_contracts::CertificateExecutionDispositionV2;

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2, SimulationFixedClock,
    certificate_test_chain_v2::{administrator, chain, fence, pending},
    certificate_test_completion_v2::completion,
    certificate_test_keys_v2::SUBJECT,
    certificate_test_signer_v2::sign_and_release,
    clock::AdministratorClock,
};

#[test]
fn issue_uses_pending_then_monotonic_promotion_and_one_use_handoff() {
    let fixture = chain(CertificateActionV2::Issue, 1, 0, None);
    let mut administrator = administrator();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 0);
    assert_eq!(pending(&administrator), 1);

    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    let signed = sign_and_release(&mut administrator, &channel, &fixture.command.jti);
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 1);
    assert_eq!(pending(&administrator), 0);
    let replayed = administrator
        .release_signed_certificate_execution_v2(&channel, &fixture.command.jti)
        .unwrap();
    assert_eq!(signed, replayed);
    let completion = completion(
        &fixture,
        &signed,
        1,
        CertificateExecutionDispositionV2::Completed,
    );
    administrator
        .complete_certificate_execution_v2(&channel, &completion.input())
        .unwrap();
    assert_eq!(
        administrator
            .certificate_execution_status_v2(&fixture.command.jti)
            .unwrap()
            .state,
        "consumed"
    );
}

#[test]
fn expired_never_handed_reservation_discards_only_pending_state() {
    let fixture = chain(CertificateActionV2::Issue, 2, 0, None);
    let mut administrator = administrator();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    administrator.clock = AdministratorClock::simulation(
        SimulationFixedClock::new("2026-07-29T00:01:00.000Z").unwrap(),
    );
    administrator
        .abandon_expired_certificate_reservation_v2(&fixture.command.jti)
        .unwrap();
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 0);
    assert_eq!(pending(&administrator), 0);
    assert_eq!(
        administrator
            .certificate_execution_status_v2(&fixture.command.jti)
            .unwrap()
            .state,
        "abandoned"
    );
}

#[test]
fn unknown_outcome_requires_the_exact_released_lease_digest() {
    let fixture = chain(CertificateActionV2::Issue, 3, 0, None);
    let mut administrator = administrator();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    let signed = sign_and_release(&mut administrator, &channel, &fixture.command.jti);
    assert!(matches!(
        administrator.mark_certificate_result_unknown_v2(
            &channel,
            &fixture.command.jti,
            &"99".repeat(32),
            &"42".repeat(32)
        ),
        Err(AdministratorError::Replay)
    ));
    administrator
        .mark_certificate_result_unknown_v2(
            &channel,
            &fixture.command.jti,
            signed.lease_digest_sha256(),
            &"42".repeat(32),
        )
        .unwrap();
}
