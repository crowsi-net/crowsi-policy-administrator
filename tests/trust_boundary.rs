use crate::support;

use crowsi_control_contracts::ControlAction;
use crowsi_policy_administrator::{AdministratorError, ArtifactRole, KeyScope, TrustedKeys};

use support::Fixture;

#[test]
fn caller_cannot_backdate_the_policy_evaluation_clock() {
    let fixture = Fixture::new().expect("fixture");
    let mut administrator = fixture
        .administrator_at("2026-07-29T00:03:00.000Z")
        .expect("administrator");
    assert!(matches!(
        administrator.reserve(&fixture.reservation(0, 1)),
        Err(AdministratorError::Contract(_))
    ));
}

#[test]
fn higher_authoritative_epoch_blocks_later_rollback() {
    let first = Fixture::version(1, 7, ControlAction::Quarantine).expect("first");
    let current = Fixture::version(2, 8, ControlAction::Quarantine).expect("current");
    let rollback = Fixture::version(3, 7, ControlAction::Quarantine).expect("rollback");
    let mut administrator = first.administrator().expect("administrator");
    administrator
        .reserve(&first.reservation(0, 1))
        .expect("epoch seven");
    administrator
        .reserve(&current.reservation(1, 2))
        .expect("epoch eight");
    assert!(matches!(
        administrator.reserve(&rollback.reservation(2, 3)),
        Err(AdministratorError::Revoked)
    ));
}

#[test]
fn newer_epoch_survives_a_conflicting_resource_reservation() {
    let first = Fixture::version(1, 7, ControlAction::Quarantine).expect("first");
    let current = Fixture::version(2, 8, ControlAction::Quarantine).expect("current");
    let rollback = Fixture::version(3, 7, ControlAction::Quarantine).expect("rollback");
    let mut administrator = first.administrator().expect("administrator");
    administrator
        .reserve(&first.reservation(0, 1))
        .expect("epoch seven");
    assert!(matches!(
        administrator.reserve(&current.reservation(0, 1)),
        Err(AdministratorError::EpochConflict)
    ));
    assert!(matches!(
        administrator.reserve(&rollback.reservation(1, 2)),
        Err(AdministratorError::Revoked)
    ));
}

#[test]
fn newer_epoch_survives_a_policy_denial() {
    let first = Fixture::version(1, 7, ControlAction::Quarantine).expect("first");
    let mut current = Fixture::version(2, 8, ControlAction::Quarantine).expect("current");
    let rollback = Fixture::version(3, 7, ControlAction::Quarantine).expect("rollback");
    current.policy_information.risk_score = 100;
    current.policy_information.signed = current
        .authorities
        .policy_information
        .sign(&current.policy_information)
        .expect("re-sign");
    let mut administrator = first.administrator().expect("administrator");
    administrator
        .reserve(&first.reservation(0, 1))
        .expect("epoch seven");
    assert!(matches!(
        administrator.reserve(&current.reservation(1, 2)),
        Err(AdministratorError::PolicyDenied)
    ));
    assert!(matches!(
        administrator.reserve(&rollback.reservation(1, 2)),
        Err(AdministratorError::Revoked)
    ));
}

#[test]
fn receipt_role_cannot_sign_an_isolation_command() {
    let mut fixture = Fixture::new().expect("fixture");
    fixture.command.signed = fixture
        .authorities
        .receipt
        .sign(&fixture.command)
        .expect("attacker signature");
    let mut administrator = fixture.administrator().expect("administrator");
    assert!(matches!(
        administrator.reserve(&fixture.reservation(0, 1)),
        Err(AdministratorError::Trust)
    ));
}

#[test]
fn one_key_material_cannot_be_registered_for_two_roles() {
    let fixture = Fixture::new().expect("fixture");
    let bytes = fixture.authorities.identity.verifying_key();
    let mut keys = TrustedKeys::default();
    keys.insert_ed25519(
        "identity.attack.1",
        ArtifactRole::Identity,
        KeyScope::Identity {
            issuer: fixture.identity.issuer.clone(),
            audience: fixture.identity.audience.clone(),
        },
        bytes,
    )
    .expect("first role");
    assert!(matches!(
        keys.insert_ed25519(
            "receipt.attack.1",
            ArtifactRole::Receipt,
            KeyScope::Provider(fixture.command.provider.clone()),
            bytes,
        ),
        Err(AdministratorError::Trust)
    ));
}

#[test]
fn weak_ed25519_verifier_is_not_trusted() {
    let mut keys = TrustedKeys::default();
    assert!(matches!(
        keys.insert_ed25519(
            "weak.control.1",
            ArtifactRole::Receipt,
            KeyScope::Provider("crowsi-enforcer-incus".into()),
            [0; 32],
        ),
        Err(AdministratorError::Trust)
    ));
}
