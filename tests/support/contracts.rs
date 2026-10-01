use crowsi_control_contracts::{
    ActionBindingV1, ActionCoverageV1, AssuranceLevel, COVERAGE_ASSERTION_SCHEMA_V1,
    CapabilityStatus, ControlAction, ControlChannel, CoverageAssertionV1, CoverageLevel,
    EnforcementReadiness, Freshness, Health, Management, ManagementLifeline,
    SECURITY_INTENT_SCHEMA_V1, SecurityIntentV1, SignatureAlgorithm, SignedDigestV1,
    VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1, Verification, VerifiedIdentityContextV1,
};

pub fn digest() -> String {
    format!("sha256:{}", "a".repeat(64))
}

pub fn signed() -> SignedDigestV1 {
    SignedDigestV1 {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: "placeholder.control.1".into(),
        digest: digest(),
        signature: "a".repeat(86),
    }
}

pub fn binding(action: ControlAction) -> ActionBindingV1 {
    ActionBindingV1 {
        audience: "crowsi-enforcer-incus".into(),
        resource: "incus://project/default/instance/worker-a".into(),
        action,
        purpose: "incident-containment".into(),
        channel: ControlChannel::EmergencyConsole,
    }
}

pub fn identity(epoch: u64, serial: u64) -> VerifiedIdentityContextV1 {
    VerifiedIdentityContextV1 {
        schema: VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1.into(),
        context_id: format!("context.{serial}"),
        issuer: "https://identity.example.test".into(),
        pairwise_subject: "subject-a".into(),
        actor: "operator-a".into(),
        device: "device-a".into(),
        workload: "spiffe://crowsi.local/rescue-console/a".into(),
        profile: "security-operator".into(),
        proof_key_ref: "proof-key-a".into(),
        assurance: AssuranceLevel::HardwareBoundStepUp,
        authorization_grant_id: format!("authorization-{serial}"),
        revocation_epoch: epoch,
        authenticated_at: "2026-07-29T00:00:00.000Z".into(),
        expires_at: "2026-07-29T00:10:00.000Z".into(),
        audience: "crowsi-enforcer-incus".into(),
        signed: signed(),
    }
}

pub fn intent(
    identity: &VerifiedIdentityContextV1,
    action: ControlAction,
    serial: u64,
) -> SecurityIntentV1 {
    SecurityIntentV1 {
        schema: SECURITY_INTENT_SCHEMA_V1.into(),
        intent_id: format!("intent.{serial}"),
        jti: format!("jti.intent.{serial}"),
        identity_context_id: identity.context_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        actor: identity.actor.clone(),
        device: identity.device.clone(),
        workload: identity.workload.clone(),
        profile: identity.profile.clone(),
        proof_key_ref: identity.proof_key_ref.clone(),
        revocation_epoch: identity.revocation_epoch,
        binding: binding(action),
        requested_at: "2026-07-29T00:01:00.000Z".into(),
        expires_at: "2026-07-29T00:05:00.000Z".into(),
        reason: "contain a verified incident".into(),
        signed: signed(),
    }
}

pub fn coverage(resource: &str, serial: u64) -> CoverageAssertionV1 {
    CoverageAssertionV1 {
        schema: COVERAGE_ASSERTION_SCHEMA_V1.into(),
        assertion_id: format!("coverage.{serial}"),
        resource: resource.into(),
        observer_id: "crowsi-independent-sensor".into(),
        coverage: CoverageLevel::Complete,
        freshness: Freshness::Fresh,
        management: Management::Managed,
        verification: Verification::Verified,
        health: Health::Healthy,
        management_lifeline: ManagementLifeline::Verified,
        enforcement_readiness: EnforcementReadiness::Ready,
        action_coverage: ActionCoverageV1 {
            quarantine: CapabilityStatus::Ready,
            revoke: CapabilityStatus::Ready,
            verify: CapabilityStatus::Ready,
            restore: CapabilityStatus::Ready,
        },
        observed_at: "2026-07-29T00:01:00.000Z".into(),
        valid_until: "2026-07-29T00:05:00.000Z".into(),
        evidence_digest: digest(),
        signed: signed(),
    }
}
