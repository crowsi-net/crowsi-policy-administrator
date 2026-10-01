use crate::support;

use crowsi_control_contracts::EnforcementReceiptV2;
use crowsi_policy_administrator::{
    AdministratorError, EnforcementPointV2, PepExecutionLeaseV2, PepExecutionUncertainV2,
};
use support::TestLedger;
use support::V2Fixture;

struct SuccessfulPep {
    receipt: Option<EnforcementReceiptV2>,
}

impl EnforcementPointV2 for SuccessfulPep {
    fn compare_and_swap(
        &mut self,
        _lease: &PepExecutionLeaseV2,
    ) -> Result<EnforcementReceiptV2, PepExecutionUncertainV2> {
        Ok(self.receipt.take().expect("one call"))
    }
}

struct UncertainPep;

impl EnforcementPointV2 for UncertainPep {
    fn compare_and_swap(
        &mut self,
        _lease: &PepExecutionLeaseV2,
    ) -> Result<EnforcementReceiptV2, PepExecutionUncertainV2> {
        Err(PepExecutionUncertainV2::new(&format!("sha256:{}", "d".repeat(64))).expect("evidence"))
    }
}

#[test]
fn committed_lease_executes_one_provider_cas() {
    let fixture = V2Fixture::new().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    administrator
        .reserve_v2(&fixture.reservation())
        .expect("reservation");
    let mut pep = SuccessfulPep {
        receipt: Some(fixture.receipt().expect("receipt")),
    };
    let status = administrator
        .execute_v2(&fixture.command.jti, &mut pep)
        .expect("execution");
    assert_eq!(status.state, "applied");
    assert!(matches!(
        administrator.execute_v2(&fixture.command.jti, &mut pep),
        Err(AdministratorError::Replay)
    ));
}

#[test]
fn unknown_transport_result_locks_until_exact_signed_reconciliation() {
    let fixture = V2Fixture::new().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    administrator
        .reserve_v2(&fixture.reservation())
        .expect("reservation");
    assert!(matches!(
        administrator.execute_v2(&fixture.command.jti, &mut UncertainPep),
        Err(AdministratorError::OutcomeUnknown)
    ));
    assert_eq!(
        administrator
            .status_v2(&fixture.command.jti)
            .expect("status")
            .state,
        "result-unknown"
    );
    administrator
        .reconcile_unknown_v2(&fixture.receipt().expect("receipt"))
        .expect("signed reconciliation");
    assert_eq!(
        administrator
            .status_v2(&fixture.command.jti)
            .expect("status")
            .state,
        "applied"
    );
}

#[test]
fn mismatched_reconciliation_remains_fail_closed() {
    let fixture = V2Fixture::new().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    administrator
        .reserve_v2(&fixture.reservation())
        .expect("reservation");
    assert!(
        administrator
            .execute_v2(&fixture.command.jti, &mut UncertainPep)
            .is_err()
    );
    let mut receipt = fixture.receipt().expect("receipt");
    receipt.fence_epoch += 1;
    receipt.signed = fixture
        .base
        .authorities
        .receipt
        .sign(&receipt)
        .expect("sign");
    assert!(administrator.reconcile_unknown_v2(&receipt).is_err());
    assert_eq!(
        administrator
            .status_v2(&fixture.command.jti)
            .expect("status")
            .state,
        "result-unknown"
    );
}

#[test]
fn process_restart_preserves_the_execution_lock() {
    let ledger = TestLedger::new();
    let fixture = V2Fixture::new().expect("fixture");
    {
        let mut administrator = fixture
            .base
            .administrator_on_path_at(ledger.path(), support::FIXED_NOW)
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
        .administrator_on_path_at(ledger.path(), support::FIXED_NOW)
        .expect("reopened");
    assert_eq!(
        reopened
            .status_v2(&fixture.command.jti)
            .expect("status")
            .state,
        "executing"
    );
    reopened
        .mark_result_unknown_v2(&fixture.command.jti, &format!("sha256:{}", "e".repeat(64)))
        .expect("unknown");
    reopened
        .reconcile_unknown_v2(&fixture.receipt().expect("receipt"))
        .expect("reconciled");
}
