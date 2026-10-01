use crate::support;

use crowsi_policy_administrator::AdministratorError;
use support::{TestLedger, V2Fixture};

#[test]
fn v2_reservation_rejects_clock_rollback_after_reopen() {
    let ledger = TestLedger::new();
    let first = V2Fixture::new().expect("first");
    {
        let mut administrator = first
            .base
            .administrator_on_path_at(ledger.path(), "2026-07-29T00:02:00.000Z")
            .expect("administrator");
        administrator
            .reserve_v2(&first.reservation())
            .expect("reservation");
    }
    let second = V2Fixture::version(2, 1, 2).expect("second");
    let mut reopened = second
        .base
        .administrator_on_path_at(ledger.path(), "2026-07-29T00:01:59.999Z")
        .expect("reopened");
    assert!(matches!(
        reopened.reserve_v2(&second.reservation()),
        Err(AdministratorError::ClockRollback)
    ));
}

#[test]
fn unknown_result_transition_rejects_clock_rollback() {
    let ledger = TestLedger::new();
    let fixture = V2Fixture::new().expect("fixture");
    {
        let mut administrator = fixture
            .base
            .administrator_on_path_at(ledger.path(), "2026-07-29T00:02:00.000Z")
            .expect("administrator");
        administrator
            .reserve_v2(&fixture.reservation())
            .expect("reservation");
        administrator
            .begin_execution_v2(&fixture.command.jti)
            .expect("lease");
    }
    let mut reopened = fixture
        .base
        .administrator_on_path_at(ledger.path(), "2026-07-29T00:01:59.999Z")
        .expect("reopened");
    assert!(matches!(
        reopened
            .mark_result_unknown_v2(&fixture.command.jti, &format!("sha256:{}", "f".repeat(64))),
        Err(AdministratorError::ClockRollback)
    ));
}
