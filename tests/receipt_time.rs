use crate::support;

use crowsi_policy_administrator::AdministratorError;

use support::Fixture;

#[test]
fn receipt_cannot_claim_execution_before_reservation() {
    let fixture = Fixture::new().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    administrator
        .reserve(&fixture.reservation(0, 1))
        .expect("reservation");
    let mut receipt = fixture.receipt().expect("receipt");
    receipt.applied_at = "2026-07-29T00:01:59.999Z".into();
    receipt.signed = fixture.authorities.receipt.sign(&receipt).expect("re-sign");
    assert!(matches!(
        administrator.record_receipt(&receipt),
        Err(AdministratorError::ReceiptMismatch)
    ));
}

#[test]
fn receipt_cannot_claim_execution_in_the_trusted_clocks_future() {
    let fixture = Fixture::new().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    administrator
        .reserve(&fixture.reservation(0, 1))
        .expect("reservation");
    let mut receipt = fixture.receipt().expect("receipt");
    receipt.applied_at = "2026-07-29T00:02:00.001Z".into();
    receipt.signed = fixture.authorities.receipt.sign(&receipt).expect("re-sign");
    assert!(matches!(
        administrator.record_receipt(&receipt),
        Err(AdministratorError::ReceiptMismatch)
    ));
}
