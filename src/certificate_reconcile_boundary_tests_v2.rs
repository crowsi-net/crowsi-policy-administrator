use crowsi_control_contracts::{
    CertificateActionV2, CertificateExecutionDispositionV2, CertificateLifecycleActionV2,
    CertificateOperationBindingV2, CertificatePayloadV2,
};

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2,
    certificate_test_chain_v2::{administrator, chain, rebind},
    certificate_test_completion_v2::reconciliation_completion,
    certificate_test_keys_v2::SUBJECT,
    certificate_test_signer_v2::sign_and_release,
};

#[test]
fn original_row_domain_or_target_substitution_cannot_complete_reconciliation() {
    let original = chain(CertificateActionV2::Issue, 92, 0, None);
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
    let mut reconcile = chain(
        CertificateActionV2::ReconcileUnknown,
        93,
        0,
        Some(operation),
    );
    reconcile.command.related_authorization_jti = Some(original.command.jti.clone());
    rebind(&mut reconcile);
    administrator
        .reserve_certificate_execution_v2(&reconcile.input())
        .unwrap();
    let reconcile_signed = sign_and_release(&mut administrator, &channel, &reconcile.command.jti);
    let completed = reconciliation_completion(
        &reconcile,
        &reconcile_signed,
        &original,
        &original_signed,
        93,
        CertificateExecutionDispositionV2::NotExecuted,
    );
    administrator
        .connection
        .execute(
            "UPDATE certificate_v2_reservations
                SET security_domain = 'security.substituted',
                    target_resource_id = 'resource.certificate.substituted'
              WHERE authorization_jti = ?",
            [&original.command.jti],
        )
        .unwrap();
    assert!(matches!(
        administrator.complete_certificate_execution_v2(&channel, &completed.input()),
        Err(AdministratorError::Binding | AdministratorError::LedgerIntegrity)
    ));
    assert_eq!(
        administrator
            .certificate_execution_status_v2(&reconcile.command.jti)
            .unwrap()
            .state,
        "executing"
    );
}
