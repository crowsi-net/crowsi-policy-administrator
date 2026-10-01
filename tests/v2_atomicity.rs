use crate::support;

use crowsi_policy_administrator::AdministratorError;
use std::sync::{Arc, Barrier};
use support::{TestLedger, V2Fixture};

#[test]
fn v2_consumes_grant_release_and_fence_once_across_reopen() {
    let ledger = TestLedger::new();
    let first = V2Fixture::new().expect("first fixture");
    {
        let mut administrator = first
            .base
            .administrator_on_path_at(ledger.path(), support::FIXED_NOW)
            .expect("first administrator");
        let reserved = administrator
            .reserve_v2(&first.reservation())
            .expect("atomic reservation");
        assert_eq!(reserved.fence_epoch, 1);
        assert_eq!(
            reserved.release_reservation_id,
            first.command.release_reservation_id
        );
    }
    let mut reopened = first
        .base
        .administrator_on_path_at(ledger.path(), support::FIXED_NOW)
        .expect("reopened administrator");
    assert!(matches!(
        reopened.reserve_v2(&first.reservation()),
        Err(AdministratorError::Replay | AdministratorError::FenceConflict)
    ));
}

#[test]
fn signed_previous_and_next_fence_are_compared_atomically() {
    let fixture = V2Fixture::version(1, 4, 5).expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    assert!(matches!(
        administrator.reserve_v2(&fixture.reservation()),
        Err(AdministratorError::FenceConflict)
    ));
}

#[test]
fn unresolved_command_blocks_the_resource_head() {
    let first = V2Fixture::new().expect("first");
    let second = V2Fixture::version(2, 1, 2).expect("second");
    let mut administrator = first.administrator().expect("administrator");
    administrator
        .reserve_v2(&first.reservation())
        .expect("first reservation");
    assert!(matches!(
        administrator.reserve_v2(&second.reservation()),
        Err(AdministratorError::OutcomeUnknown)
    ));
}

#[test]
fn two_process_equivalent_connections_cannot_win_the_same_head() {
    let ledger = TestLedger::new();
    {
        let fixture = V2Fixture::new().expect("initializer");
        fixture
            .base
            .administrator_on_path_at(ledger.path(), support::FIXED_NOW)
            .expect("initialized ledger");
    }
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let path = ledger.path().to_path_buf();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let fixture = V2Fixture::new().expect("fixture");
                let mut administrator = fixture
                    .base
                    .administrator_on_path_at(&path, support::FIXED_NOW)
                    .expect("administrator");
                barrier.wait();
                administrator.reserve_v2(&fixture.reservation())
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
}

#[test]
fn security_domain_or_release_tampering_never_advances_the_head() {
    let mut fixture = V2Fixture::new().expect("fixture");
    fixture.command.security_domain = "customer-other".into();
    fixture.command.signed = fixture
        .base
        .authorities
        .command
        .sign(&fixture.command)
        .expect("sign");
    let mut administrator = fixture.administrator().expect("administrator");
    assert!(matches!(
        administrator.reserve_v2(&fixture.reservation()),
        Err(AdministratorError::Binding)
    ));
}
