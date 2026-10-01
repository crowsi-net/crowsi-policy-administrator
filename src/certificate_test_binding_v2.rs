use crowsi_control_contracts::{
    CertificateActionV2, CertificateApprovalEvidenceV2, CertificateAuthorizationBindingV2,
    CertificateDeploymentBindingV2, CertificateIdentityBindingV2, CertificateOperationBindingV2,
    CertificatePayloadV2, CertificateRevocationBindingV2, CertificateRevocationEvidenceV2,
    CertificateTargetBindingV2,
};

use crate::{
    certificate_test_evidence_v2::{approval, revocation},
    certificate_test_keys_v2::{SUBJECT, approval_signature, policy, revocation_signature},
};

pub(crate) struct BindingFixture {
    pub(crate) binding: CertificateAuthorizationBindingV2,
    pub(crate) approval: Option<CertificateApprovalEvidenceV2>,
    pub(crate) revocation: CertificateRevocationEvidenceV2,
}

pub(crate) fn binding(
    action: CertificateActionV2,
    serial: u64,
    previous_fence: u64,
    operation: Option<CertificateOperationBindingV2>,
) -> BindingFixture {
    let target = target(action, previous_fence, operation.as_ref());
    let mut approval = action
        .requires_separation_of_duties()
        .then(|| approval(action, serial, &target));
    if let Some(evidence) = approval.as_mut() {
        evidence.signed = approval_signature(evidence);
    }
    let mut revocation = revocation(serial);
    revocation.signed = revocation_signature(&revocation);
    let policy = policy();
    let binding = CertificateAuthorizationBindingV2 {
        issuer: policy.authorization_issuer,
        audience: policy.authorization_audience,
        channel: policy.authorization_channel,
        approval_id: approval.as_ref().map(|value| value.approval_id.clone()),
        approval_evidence_digest_sha256: approval
            .as_ref()
            .map(CertificatePayloadV2::certificate_digest_sha256),
        approval_method: approval.as_ref().map(|value| value.method),
        approval_assurance: approval.as_ref().map(|value| value.assurance),
        approval_issued_at_epoch_s: approval.as_ref().map(|value| value.issued_at_epoch_s),
        approval_expires_at_epoch_s: approval.as_ref().map(|value| value.expires_at_epoch_s),
        approval_verified_at_epoch_s: approval.as_ref().map(|value| value.issued_at_epoch_s),
        policy_id: policy.authorization_policy_id,
        policy_digest_sha256: policy.authorization_policy_digest_sha256,
        identity: identity(action),
        deployment: deployment(serial),
        revocation: CertificateRevocationBindingV2 {
            snapshot_id: revocation.snapshot_id.clone(),
            snapshot_digest_sha256: revocation.certificate_digest_sha256(),
            previous_identity_revocation_epoch: revocation.previous_identity_revocation_epoch,
            snapshot_epoch: revocation.identity_revocation_epoch,
            snapshot_verified_at_epoch_s: revocation.verified_at_epoch_s,
            authoritative: revocation.authoritative,
        },
        target,
        operation,
    };
    BindingFixture {
        binding,
        approval,
        revocation,
    }
}

fn identity(action: CertificateActionV2) -> CertificateIdentityBindingV2 {
    let approval = action.requires_separation_of_duties();
    CertificateIdentityBindingV2 {
        pairwise_subject: SUBJECT.into(),
        requester_pairwise_subject: "subject.requester.nerp".into(),
        requester_actor: "actor.nerp.operator".into(),
        requester_device: "device.local.0001".into(),
        requester_profile: "profile.workload.operator".into(),
        requester_proof_key_ref: "proof.key.local.0001".into(),
        approver_pairwise_subject: approval.then(|| "subject.approver.security".into()),
        approver_actor: approval.then(|| "actor.security.approver".into()),
        approver_device: approval.then(|| "device.security.0001".into()),
        approver_profile: approval.then(|| "profile.security.approver".into()),
        approver_proof_key_ref: approval.then(|| "proof.key.security.0001".into()),
        workload: "spiffe://crowsi.test/local/nerp".into(),
        identity_revocation_epoch: 9,
    }
}

fn deployment(serial: u64) -> CertificateDeploymentBindingV2 {
    CertificateDeploymentBindingV2 {
        security_domain: "security.crowsi".into(),
        deployment_id: "deployment.local".into(),
        release_id: format!("release.certificate.{serial:04}"),
        release_digest_sha256: "31".repeat(32),
        checkpoint_id: "checkpoint.certificate.0001".into(),
        checkpoint_digest_sha256: "32".repeat(32),
        checkpoint_sequence: 3,
        deployment_provenance_ref: "deployment.provenance.shared".into(),
        trust_revision: 7,
    }
}

fn target(
    action: CertificateActionV2,
    previous_fence: u64,
    operation: Option<&CertificateOperationBindingV2>,
) -> CertificateTargetBindingV2 {
    let read = matches!(
        action,
        CertificateActionV2::CertificateStatus | CertificateActionV2::OperationStatus
    );
    let mut previous_lifecycle = match action {
        CertificateActionV2::Issue | CertificateActionV2::CertificateStatus => 0,
        _ => 3,
    };
    let mut lifecycle = previous_lifecycle + u64::from(action == CertificateActionV2::Revoke);
    let mut version = u64::from(action != CertificateActionV2::Issue);
    if let Some(CertificateOperationBindingV2::ReconcileUnknown {
        original_action,
        locked_previous_lifecycle_revocation_epoch,
        locked_lifecycle_revocation_epoch,
        ..
    }) = operation
    {
        previous_lifecycle = *locked_previous_lifecycle_revocation_epoch;
        lifecycle = *locked_lifecycle_revocation_epoch;
        version = u64::from(
            *original_action != crowsi_control_contracts::CertificateLifecycleActionV2::Issue,
        );
    }
    CertificateTargetBindingV2 {
        service_id: "service.nerp.local".into(),
        provider: "provider.policy.administrator".into(),
        target_resource_id: "resource.certificate.nerp.worker".into(),
        target_resource_normalizer_id: "normalizer.certificate.target".into(),
        target_resource_normalizer_version: "version.0001".into(),
        target_resource_normalization_digest_sha256:
            crowsi_control_contracts::certificate_target_normalization_digest_v2(
                "provider.policy.administrator",
                "resource.certificate.nerp.worker",
                "resource.certificate.nerp.worker",
                "normalizer.certificate.target",
                "version.0001",
            ),
        target_resource_normalization_verified: true,
        previous_fence,
        current_fence: previous_fence + u64::from(!read),
        expected_resource_version: version,
        previous_lifecycle_revocation_epoch: previous_lifecycle,
        lifecycle_revocation_epoch: lifecycle,
    }
}
