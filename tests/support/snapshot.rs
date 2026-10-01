use crowsi_control_contracts::{
    CanonicalPayloadV1, ControlAction, CoverageAssertionV1, IncidentAssertionV1,
    ManagementAuthorityAssertionV1, POLICY_INFORMATION_SNAPSHOT_SCHEMA_V1, PolicyAuthorityState,
    PolicyIncidentState, PolicyInformationSnapshotV1, PolicyPostureState, PostureAssertionV1,
    RECOVERY_AUTHORIZATION_SCHEMA_V1, RecoveryAuthorizationV1, SecurityIntentV1,
    VerifiedIdentityContextV1,
};

use super::contracts::signed;

pub fn snapshot(
    identity: &VerifiedIdentityContextV1,
    intent: &SecurityIntentV1,
    coverage: &CoverageAssertionV1,
    policy_digest: &str,
    serial: u64,
) -> PolicyInformationSnapshotV1 {
    let window = || PostureAssertionV1 {
        target: String::new(),
        state: PolicyPostureState::Trusted,
        observed_at: "2026-07-29T00:01:00.000Z".into(),
        valid_until: "2026-07-29T00:05:00.000Z".into(),
    };
    let mut device = window();
    device.target.clone_from(&identity.device);
    let mut workload = window();
    workload.target.clone_from(&identity.workload);
    let incident_state = if intent.binding.action == ControlAction::Restore {
        PolicyIncidentState::RecoveryAuthorized
    } else {
        PolicyIncidentState::ContainmentRequested
    };
    PolicyInformationSnapshotV1 {
        schema: POLICY_INFORMATION_SNAPSHOT_SCHEMA_V1.into(),
        snapshot_id: format!("snapshot.{serial}"),
        identity_context_id: identity.context_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        device_posture: device,
        workload_posture: workload,
        incident: IncidentAssertionV1 {
            incident_id: format!("incident.{serial}"),
            resource: intent.binding.resource.clone(),
            state: incident_state,
            observed_at: "2026-07-29T00:01:00.000Z".into(),
            valid_until: "2026-07-29T00:05:00.000Z".into(),
        },
        management_authority: ManagementAuthorityAssertionV1 {
            state: PolicyAuthorityState::Authorized,
            identity_context_id: identity.context_id.clone(),
            authorization_grant_id: identity.authorization_grant_id.clone(),
            revocation_epoch: identity.revocation_epoch,
            binding: intent.binding.clone(),
            observed_at: "2026-07-29T00:01:00.000Z".into(),
            valid_until: "2026-07-29T00:05:00.000Z".into(),
        },
        authoritative_revocation_epoch: identity.revocation_epoch,
        risk_score: 10,
        coverage_assertion_id: coverage.assertion_id.clone(),
        coverage_digest: coverage.payload_digest(),
        policy_digest: policy_digest.into(),
        issued_at: "2026-07-29T00:01:05.000Z".into(),
        expires_at: "2026-07-29T00:02:05.000Z".into(),
        signed: signed(),
    }
}

pub fn recovery(
    identity: &VerifiedIdentityContextV1,
    intent: &SecurityIntentV1,
    snapshot: &PolicyInformationSnapshotV1,
    serial: u64,
) -> RecoveryAuthorizationV1 {
    RecoveryAuthorizationV1 {
        schema: RECOVERY_AUTHORIZATION_SCHEMA_V1.into(),
        authorization_id: format!("recovery.{serial}"),
        jti: format!("jti.recovery.{serial}"),
        identity_context_id: identity.context_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        binding: intent.binding.clone(),
        incident_id: snapshot.incident.incident_id.clone(),
        policy_snapshot_id: snapshot.snapshot_id.clone(),
        policy_snapshot_digest: snapshot.payload_digest(),
        authoritative_revocation_epoch: snapshot.authoritative_revocation_epoch,
        issued_at: "2026-07-29T00:01:30.000Z".into(),
        expires_at: "2026-07-29T00:02:30.000Z".into(),
        use_limit: 1,
        signed: signed(),
    }
}
