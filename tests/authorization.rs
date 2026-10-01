use crate::support;

use crowsi_policy_administrator::AdministratorError;

use support::Fixture;

#[test]
fn signed_grant_is_consumed_once_and_epoch_advances() {
    let fixture = Fixture::new().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    let reservation = administrator
        .reserve(&fixture.reservation(0, 1))
        .expect("first reservation");
    assert_eq!(reservation.isolation_epoch, 1);
    assert!(matches!(
        administrator.reserve(&fixture.reservation(0, 1)),
        Err(AdministratorError::EpochConflict | AdministratorError::Replay)
    ));
}

#[test]
fn tampering_a_signed_resource_fails_closed() {
    let mut fixture = Fixture::new().expect("fixture");
    fixture.command.binding.resource.push_str("/other");
    let mut administrator = fixture.administrator().expect("administrator");
    assert!(matches!(
        administrator.reserve(&fixture.reservation(0, 1)),
        Err(AdministratorError::Signature)
    ));
}

#[test]
fn stale_revocation_epoch_does_not_advance_state() {
    let mut fixture = Fixture::new().expect("fixture");
    fixture.identity.revocation_epoch = 6;
    fixture.identity.signed = fixture
        .authorities
        .identity
        .sign(&fixture.identity)
        .expect("sign");
    let mut administrator = fixture.administrator().expect("administrator");
    assert!(administrator.reserve(&fixture.reservation(0, 1)).is_err());
    assert!(matches!(
        administrator.status(&fixture.command.binding.resource),
        Err(AdministratorError::ReceiptMismatch)
    ));
}

#[test]
fn epoch_must_advance_by_exactly_one() {
    let fixture = Fixture::new().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    assert!(matches!(
        administrator.reserve(&fixture.reservation(0, 2)),
        Err(AdministratorError::EpochConflict)
    ));
}
