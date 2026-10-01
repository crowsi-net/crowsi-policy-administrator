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
fn not_executed_reconciliation_never_rolls_back_promoted_lifecycle_epoch() {
    let original = chain(CertificateActionV2::Revoke, 81, 0, None);
    let mut administrator = administrator();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    administrator
        .connection
        .execute(
            "INSERT INTO certificate_v2_lifecycle_epochs
             VALUES (?, ?, ?, ?, 3)",
            [
                &original.command.binding.deployment.security_domain,
                &original.command.binding.deployment.deployment_id,
                &original.command.binding.target.provider,
                &original.command.binding.target.target_resource_id,
            ],
        )
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
    assert_eq!(lifecycle_epoch(&administrator), 4);

    let operation = CertificateOperationBindingV2::ReconcileUnknown {
        original_action: CertificateLifecycleActionV2::Revoke,
        target_operation_id: original.command.operation_id.clone(),
        lifecycle_reservation_id: original.command.pa_reservation_id.clone(),
        authority_command_digest_sha256: original.command.certificate_digest_sha256(),
        unknown_evidence_digest_sha256: "42".repeat(32),
        locked_previous_fence: 0,
        locked_current_fence: 1,
        locked_previous_lifecycle_revocation_epoch: 3,
        locked_lifecycle_revocation_epoch: 4,
    };
    let mut reconcile = chain(
        CertificateActionV2::ReconcileUnknown,
        82,
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
        82,
        CertificateExecutionDispositionV2::NotExecuted,
    );
    administrator
        .complete_certificate_execution_v2(&channel, &completed.input())
        .unwrap();
    assert_eq!(lifecycle_epoch(&administrator), 4);

    let stale = chain(CertificateActionV2::Renew, 83, 1, None);
    assert!(matches!(
        administrator.reserve_certificate_execution_v2(&stale.input()),
        Err(AdministratorError::EpochConflict)
    ));
    let mut current = chain(CertificateActionV2::Renew, 84, 1, None);
    current
        .parts
        .binding
        .target
        .previous_lifecycle_revocation_epoch = 4;
    current.parts.binding.target.lifecycle_revocation_epoch = 4;
    rebind(&mut current);
    administrator
        .reserve_certificate_execution_v2(&current.input())
        .unwrap();
}

fn lifecycle_epoch(administrator: &crate::CertificatePolicyAdministratorV2) -> u64 {
    administrator
        .connection
        .query_row(
            "SELECT epoch FROM certificate_v2_lifecycle_epochs
              WHERE target_resource_id = 'resource.certificate.nerp.worker'",
            [],
            |row| row.get(0),
        )
        .unwrap()
}
