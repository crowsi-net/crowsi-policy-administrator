use crowsi_control_contracts::{
    CertificateActionV2, CertificateExecutionDispositionV2, CertificateLifecycleActionV2,
    CertificateOperationBindingV2, CertificatePayloadV2,
};

use crate::{
    AuthenticatedCertificateManagerChannelV2,
    certificate_test_chain_v2::{administrator, chain, rebind},
    certificate_test_completion_v2::completion,
    certificate_test_keys_v2::SUBJECT,
    certificate_test_signer_v2::sign_and_release,
};

#[test]
fn ambiguous_reconciliation_has_repeatable_non_mutating_readback() {
    let original = chain(CertificateActionV2::Issue, 31, 0, None);
    let mut administrator = administrator();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    administrator
        .reserve_certificate_execution_v2(&original.input())
        .unwrap();
    let signed = sign_and_release(&mut administrator, &channel, &original.command.jti);
    administrator
        .mark_certificate_result_unknown_v2(
            &channel,
            &original.command.jti,
            signed.lease_digest_sha256(),
            &"42".repeat(32),
        )
        .unwrap();

    let operation = CertificateOperationBindingV2::ReconcileUnknown {
        original_action: CertificateLifecycleActionV2::Issue,
        target_operation_id: original.command.operation_id.clone(),
        lifecycle_reservation_id: original.command.pa_reservation_id.clone(),
        authority_command_digest_sha256: original.command.certificate_digest_sha256(),
        unknown_evidence_digest_sha256: "42".repeat(32),
        locked_previous_fence: 0,
        locked_current_fence: 1,
        locked_previous_lifecycle_revocation_epoch: 0,
        locked_lifecycle_revocation_epoch: 0,
    };
    let mut reconcile = chain(
        CertificateActionV2::ReconcileUnknown,
        32,
        0,
        Some(operation),
    );
    reconcile.command.related_authorization_jti = Some(original.command.jti.clone());
    administrator
        .reserve_certificate_execution_v2(&reconcile.input())
        .unwrap();
    let signed = sign_and_release(&mut administrator, &channel, &reconcile.command.jti);
    administrator
        .mark_certificate_result_unknown_v2(
            &channel,
            &reconcile.command.jti,
            signed.lease_digest_sha256(),
            &"43".repeat(32),
        )
        .unwrap();

    for serial in [33, 34] {
        let operation = CertificateOperationBindingV2::OperationStatus {
            target_operation_id: reconcile.command.operation_id.clone(),
        };
        let mut status = chain(
            CertificateActionV2::OperationStatus,
            serial,
            0,
            Some(operation),
        );
        status.parts.binding.target.expected_resource_version = 0;
        status
            .parts
            .binding
            .target
            .previous_lifecycle_revocation_epoch = 0;
        status.parts.binding.target.lifecycle_revocation_epoch = 0;
        rebind(&mut status);
        status.command.related_authorization_jti = Some(reconcile.command.jti.clone());
        administrator
            .reserve_certificate_execution_v2(&status.input())
            .unwrap();
        let signed = sign_and_release(&mut administrator, &channel, &status.command.jti);
        let completed = completion(
            &status,
            &signed,
            u8::try_from(serial).unwrap(),
            CertificateExecutionDispositionV2::Completed,
        );
        administrator
            .complete_certificate_execution_v2(&channel, &completed.input())
            .unwrap();
    }
    assert_eq!(
        administrator
            .certificate_execution_status_v2(&reconcile.command.jti)
            .unwrap()
            .state,
        "result-unknown"
    );
}
