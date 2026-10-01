use crowsi_control_contracts::{CertificateActionV2, CertificateExecutionDispositionV2};

use crate::{
    AdministratorError, AuthenticatedCertificateManagerChannelV2,
    certificate_test_chain_v2::{administrator, chain, fence},
    certificate_test_completion_v2::completion,
    certificate_test_keys_v2::{SUBJECT, approval_signature},
    certificate_test_signer_v2::sign_and_release,
};

#[test]
fn independently_signed_approval_is_exactly_principal_bound() {
    let mut fixture = chain(CertificateActionV2::Issue, 4, 0, None);
    let approval = fixture.parts.approval.as_mut().unwrap();
    approval.approver_device = "device.attacker.0001".into();
    approval.signed = approval_signature(approval);
    let mut administrator = administrator();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    assert!(matches!(
        administrator.reserve_certificate_execution_v2(&fixture.input()),
        Err(AdministratorError::Binding)
    ));
}

#[test]
fn repeated_status_reads_require_no_operator_approval_or_fence_advance() {
    let first = chain(CertificateActionV2::CertificateStatus, 5, 0, None);
    let second = chain(CertificateActionV2::CertificateStatus, 6, 0, None);
    let mut administrator = administrator();
    administrator
        .bootstrap_certificate_revocation_epoch_v2(SUBJECT, 8)
        .unwrap();
    let channel = AuthenticatedCertificateManagerChannelV2::for_simulation();
    for (fixture, serial) in [(&first, 5), (&second, 6)] {
        administrator
            .reserve_certificate_execution_v2(&fixture.input())
            .unwrap();
        let signed = sign_and_release(&mut administrator, &channel, &fixture.command.jti);
        let completed = completion(
            fixture,
            &signed,
            serial,
            CertificateExecutionDispositionV2::Completed,
        );
        administrator
            .complete_certificate_execution_v2(&channel, &completed.input())
            .unwrap();
    }
    let approval_uses: i64 = administrator
        .connection
        .query_row(
            "SELECT COUNT(*) FROM certificate_v2_approval_uses",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(approval_uses, 0);
    assert_eq!(fence(&administrator, "certificate-status"), 0);
}
