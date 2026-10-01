use crate::support;

use crowsi_policy_administrator::AdministratorError;

use support::Fixture;

#[test]
fn restore_requires_independently_scoped_recovery_authority() {
    let mut fixture = Fixture::restore().expect("fixture");
    fixture.recovery_authorization = None;
    let mut administrator = fixture.administrator().expect("administrator");
    assert!(matches!(
        administrator.reserve(&fixture.reservation(0, 1)),
        Err(AdministratorError::Trust)
    ));
}

#[test]
fn command_role_cannot_mint_recovery_authority() {
    let mut fixture = Fixture::restore().expect("fixture");
    let recovery = fixture.recovery_authorization.as_mut().expect("recovery");
    recovery.signed = fixture
        .authorities
        .command
        .sign(recovery)
        .expect("attacker signature");
    let mut administrator = fixture.administrator().expect("administrator");
    assert!(matches!(
        administrator.reserve(&fixture.reservation(0, 1)),
        Err(AdministratorError::Trust)
    ));
}

#[test]
fn recovery_authority_is_bound_to_the_exact_signed_snapshot() {
    let mut fixture = Fixture::restore().expect("fixture");
    let recovery = fixture.recovery_authorization.as_mut().expect("recovery");
    recovery.policy_snapshot_id = "snapshot.other".into();
    recovery.signed = fixture
        .authorities
        .recovery
        .sign(recovery)
        .expect("re-sign");
    let mut administrator = fixture.administrator().expect("administrator");
    assert!(matches!(
        administrator.reserve(&fixture.reservation(0, 1)),
        Err(AdministratorError::Binding)
    ));
}

#[test]
fn one_recovery_jti_cannot_authorize_two_restores() {
    let first =
        Fixture::version(1, 7, crowsi_control_contracts::ControlAction::Restore).expect("first");
    let mut second =
        Fixture::version(2, 7, crowsi_control_contracts::ControlAction::Restore).expect("second");
    let first_jti = first
        .recovery_authorization
        .as_ref()
        .expect("first recovery")
        .jti
        .clone();
    let second_recovery = second
        .recovery_authorization
        .as_mut()
        .expect("second recovery");
    second_recovery.jti = first_jti;
    second_recovery.signed = second
        .authorities
        .recovery
        .sign(second_recovery)
        .expect("re-sign");
    let mut administrator = first.administrator().expect("administrator");
    administrator
        .reserve(&first.reservation(0, 1))
        .expect("first restore");
    assert!(matches!(
        administrator.reserve(&second.reservation(1, 2)),
        Err(AdministratorError::Replay)
    ));
}

#[test]
fn exact_recovery_authority_allows_a_single_restore_reservation() {
    let fixture = Fixture::restore().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    assert_eq!(
        administrator
            .reserve(&fixture.reservation(0, 1))
            .expect("restore")
            .isolation_epoch,
        1
    );
}
