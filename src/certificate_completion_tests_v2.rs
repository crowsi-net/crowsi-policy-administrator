use crowsi_control_contracts::{
    CertificateActionV2, CertificateExecutionDispositionV2, CertificateLifecycleActionV2,
    CertificateOperationBindingV2, CertificatePayloadV2,
};

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2,
    certificate_test_chain_v2::{administrator, chain, rebind},
    certificate_test_completion_v2::{completion, reconciliation_completion},
    certificate_test_keys_v2::SUBJECT,
    certificate_test_signer_v2::sign_and_release,
};

#[test]
fn still_unknown_never_unlocks_original_and_fresh_reconciliation_can_resolve() {
    let original = chain(CertificateActionV2::Issue, 41, 0, None);
    let mut administrator = administrator();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    administrator
        .reserve_certificate_execution_v2(&original.input())
        .unwrap();
    let original_signed = sign_and_release(&mut administrator, &channel, &original.command.jti);
    administrator
        .mark_certificate_result_unknown_v2(
            &channel,
            &original.command.jti,
            original_signed.lease_digest_sha256(),
            &"42".repeat(32),
        )
        .unwrap();

    let first = reconcile(&original, 42, 0);
    administrator
        .reserve_certificate_execution_v2(&first.input())
        .unwrap();
    let first_signed = sign_and_release(&mut administrator, &channel, &first.command.jti);
    let first_completion = reconciliation_completion(
        &first,
        &first_signed,
        &original,
        &original_signed,
        42,
        CertificateExecutionDispositionV2::StillUnknown,
    );
    administrator
        .complete_certificate_execution_v2(&channel, &first_completion.input())
        .unwrap();
    assert_eq!(state(&administrator, &first.command.jti), "consumed");
    assert_eq!(
        state(&administrator, &original.command.jti),
        "result-unknown"
    );

    let blocked = chain(CertificateActionV2::Issue, 43, 1, None);
    assert!(matches!(
        administrator.reserve_certificate_execution_v2(&blocked.input()),
        Err(AdministratorError::OutcomeUnknown)
    ));

    let second = reconcile(&original, 44, 1);
    administrator
        .reserve_certificate_execution_v2(&second.input())
        .unwrap();
    let second_signed = sign_and_release(&mut administrator, &channel, &second.command.jti);
    let second_completion = reconciliation_completion(
        &second,
        &second_signed,
        &original,
        &original_signed,
        44,
        CertificateExecutionDispositionV2::NotExecuted,
    );
    administrator
        .complete_certificate_execution_v2(&channel, &second_completion.input())
        .unwrap();
    assert_eq!(state(&administrator, &second.command.jti), "consumed");
    assert_eq!(state(&administrator, &original.command.jti), "reconciled");
    let unblocked = chain(CertificateActionV2::Issue, 45, 1, None);
    administrator
        .reserve_certificate_execution_v2(&unblocked.input())
        .unwrap();
}

#[test]
fn forged_or_tampered_completion_cannot_consume_execution() {
    let fixture = chain(CertificateActionV2::Issue, 51, 0, None);
    let mut administrator = administrator();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    administrator
        .reserve_certificate_execution_v2(&fixture.input())
        .unwrap();
    let signed = sign_and_release(&mut administrator, &channel, &fixture.command.jti);
    let mut evidence = completion(
        &fixture,
        &signed,
        51,
        CertificateExecutionDispositionV2::Completed,
    );
    evidence.manager.resource_version += 1;
    assert!(matches!(
        administrator.complete_certificate_execution_v2(&channel, &evidence.input()),
        Err(AdministratorError::Contract(_))
    ));
    assert_eq!(state(&administrator, &fixture.command.jti), "executing");
}

fn reconcile(
    original: &crate::certificate_test_chain_v2::ChainFixture,
    serial: u64,
    previous_fence: u64,
) -> crate::certificate_test_chain_v2::ChainFixture {
    let target = &original.command.binding.target;
    let operation = CertificateOperationBindingV2::ReconcileUnknown {
        original_action: CertificateLifecycleActionV2::Issue,
        target_operation_id: original.command.operation_id.clone(),
        lifecycle_reservation_id: original.command.pa_reservation_id.clone(),
        authority_command_digest_sha256: original.command.certificate_digest_sha256(),
        unknown_evidence_digest_sha256: "42".repeat(32),
        locked_previous_fence: target.previous_fence,
        locked_current_fence: target.current_fence,
        locked_previous_lifecycle_revocation_epoch: target.previous_lifecycle_revocation_epoch,
        locked_lifecycle_revocation_epoch: target.lifecycle_revocation_epoch,
    };
    let mut value = chain(
        CertificateActionV2::ReconcileUnknown,
        serial,
        previous_fence,
        Some(operation),
    );
    value.command.related_authorization_jti = Some(original.command.jti.clone());
    rebind(&mut value);
    value
}

fn state(administrator: &crate::CertificatePolicyAdministratorV2, jti: &str) -> String {
    administrator
        .certificate_execution_status_v2(jti)
        .unwrap()
        .state
}
