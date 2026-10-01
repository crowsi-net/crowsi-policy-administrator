use crate::support;

use crowsi_policy_administrator::AdministratorError;

use support::Fixture;

#[test]
fn exact_signed_receipt_completes_the_reservation_idempotently() {
    let fixture = Fixture::new().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    administrator
        .reserve(&fixture.reservation(0, 1))
        .expect("reservation");
    let receipt = fixture.receipt().expect("receipt");
    let first = administrator.record_receipt(&receipt).expect("receipt");
    let repeated = administrator.record_receipt(&receipt).expect("idempotent");
    assert_eq!(first.state, "applied");
    assert_eq!(first, repeated);
    assert_eq!(
        administrator
            .status(&fixture.command.binding.resource)
            .expect("status"),
        first
    );
}

#[test]
fn a_receipt_for_another_resource_is_rejected() {
    let fixture = Fixture::new().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    administrator
        .reserve(&fixture.reservation(0, 1))
        .expect("reservation");
    let mut receipt = fixture.receipt().expect("receipt");
    receipt.binding.resource.push_str("/other");
    receipt.signed = fixture.authorities.receipt.sign(&receipt).expect("sign");
    assert!(matches!(
        administrator.record_receipt(&receipt),
        Err(AdministratorError::ReceiptMismatch)
    ));
}

#[test]
fn a_conflicting_second_receipt_is_rejected() {
    let fixture = Fixture::new().expect("fixture");
    let mut administrator = fixture.administrator().expect("administrator");
    administrator
        .reserve(&fixture.reservation(0, 1))
        .expect("reservation");
    let receipt = fixture.receipt().expect("receipt");
    administrator.record_receipt(&receipt).expect("receipt");
    let mut conflicting = receipt.clone();
    conflicting.receipt_id = "receipt.2".into();
    conflicting.signed = fixture
        .authorities
        .receipt
        .sign(&conflicting)
        .expect("sign");
    assert!(matches!(
        administrator.record_receipt(&conflicting),
        Err(AdministratorError::ReceiptMismatch)
    ));
}
