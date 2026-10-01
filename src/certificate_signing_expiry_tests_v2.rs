use crowsi_control_contracts::CertificateActionV2;

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2,
    certificate_signing_expiry_fixture_v2::{
        bootstrap, expire_clock, ready, retarget, shift_validity, states,
    },
    certificate_test_chain_v2::{administrator, chain, fence, pending},
    certificate_test_signer_v2::TestSigner,
};

#[test]
fn expired_signed_but_unreleased_authorization_is_reaped_atomically() {
    let fixture = chain(CertificateActionV2::Issue, 61, 0, None);
    let mut administrator = administrator();
    bootstrap(&mut administrator);
    ready(&mut administrator, &fixture);
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    expire_clock(&mut administrator);
    assert!(matches!(
        administrator.release_signed_certificate_execution_v2(&channel, &fixture.command.jti),
        Err(AdministratorError::Time)
    ));
    administrator
        .expire_unreleased_certificate_authorization_v2(&channel, &fixture.command.jti)
        .unwrap();
    assert_eq!(fence(&administrator, "lifecycle-mutation"), 0);
    assert_eq!(pending(&administrator), 0);
    assert_eq!(
        states(&administrator, &fixture.command.jti),
        ("expired-unreleased".into(), "abandoned".into(), 1)
    );
    assert!(matches!(
        administrator
            .expire_unreleased_certificate_authorization_v2(&channel, &fixture.command.jti),
        Err(AdministratorError::Replay)
    ));
    assert!(matches!(
        administrator.sign_certificate_execution_v2(
            &channel,
            &fixture.command.jti,
            &mut TestSigner::signed()
        ),
        Err(AdministratorError::Replay)
    ));
    let mut next = chain(CertificateActionV2::Issue, 62, 0, None);
    shift_validity(&mut next, 60);
    administrator
        .reserve_certificate_execution_v2(&next.input())
        .unwrap();
}

#[test]
fn substituted_lease_cannot_discard_either_pending_reservation() {
    let first = chain(CertificateActionV2::Issue, 63, 0, None);
    let mut second = chain(CertificateActionV2::Issue, 64, 0, None);
    retarget(&mut second, "resource.certificate.nerp.second");
    let mut administrator = administrator();
    bootstrap(&mut administrator);
    ready(&mut administrator, &first);
    ready(&mut administrator, &second);
    let second_lease: String = administrator
        .connection
        .query_row(
            "SELECT lease_json FROM certificate_v2_signing_handoffs
              WHERE authorization_jti = ?",
            [&second.command.jti],
            |row| row.get(0),
        )
        .unwrap();
    administrator
        .connection
        .execute(
            "UPDATE certificate_v2_signing_handoffs SET lease_json = ?
              WHERE authorization_jti = ?",
            [&second_lease, &first.command.jti],
        )
        .unwrap();
    expire_clock(&mut administrator);
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    assert!(matches!(
        administrator.expire_unreleased_certificate_authorization_v2(&channel, &first.command.jti),
        Err(AdministratorError::LedgerIntegrity)
    ));
    assert_eq!(pending(&administrator), 2);
    assert_eq!(states(&administrator, &first.command.jti).1, "reserved");
    assert_eq!(states(&administrator, &second.command.jti).1, "reserved");
}
