use crowsi_control_contracts::{
    ENFORCEMENT_GRANT_SCHEMA_V1, ENFORCEMENT_RECEIPT_SCHEMA_V1, EnforcementGrantV1,
    EnforcementOutcome, EnforcementReceiptV1, ISOLATION_COMMAND_SCHEMA_V1, IsolationCommandV1,
    POLICY_DECISION_SCHEMA_V1, PolicyDecisionV1, SecurityIntentV1, VerifiedIdentityContextV1,
};
use crowsi_policy_engine::PolicyEvaluation;

use super::contracts::{digest, signed};

pub fn decision(
    identity: &VerifiedIdentityContextV1,
    intent: &SecurityIntentV1,
    result: &PolicyEvaluation,
    serial: u64,
) -> PolicyDecisionV1 {
    PolicyDecisionV1 {
        schema: POLICY_DECISION_SCHEMA_V1.into(),
        decision_id: format!("decision.{serial}"),
        intent_jti: intent.jti.clone(),
        identity_context_id: identity.context_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        actor: identity.actor.clone(),
        device: identity.device.clone(),
        workload: identity.workload.clone(),
        profile: identity.profile.clone(),
        proof_key_ref: identity.proof_key_ref.clone(),
        revocation_epoch: identity.revocation_epoch,
        effect: result.effect,
        binding: result.binding.clone(),
        required_assurance: result.required_assurance,
        issued_at: "2026-07-29T00:01:10.000Z".into(),
        expires_at: "2026-07-29T00:04:30.000Z".into(),
        policy_digest: result.policy_digest.clone(),
        signed: signed(),
    }
}

pub fn grant(
    identity: &VerifiedIdentityContextV1,
    intent: &SecurityIntentV1,
    decision: &PolicyDecisionV1,
    serial: u64,
) -> EnforcementGrantV1 {
    EnforcementGrantV1 {
        schema: ENFORCEMENT_GRANT_SCHEMA_V1.into(),
        grant_id: format!("grant.{serial}"),
        jti: format!("jti.grant.{serial}"),
        decision_id: decision.decision_id.clone(),
        intent_jti: intent.jti.clone(),
        identity_context_id: identity.context_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        actor: identity.actor.clone(),
        device: identity.device.clone(),
        workload: identity.workload.clone(),
        profile: identity.profile.clone(),
        proof_key_ref: identity.proof_key_ref.clone(),
        revocation_epoch: identity.revocation_epoch,
        binding: decision.binding.clone(),
        assurance: identity.assurance,
        issued_at: "2026-07-29T00:01:20.000Z".into(),
        expires_at: "2026-07-29T00:03:20.000Z".into(),
        use_limit: 1,
        policy_digest: decision.policy_digest.clone(),
        signed: signed(),
    }
}

pub fn command(
    identity: &VerifiedIdentityContextV1,
    decision: &PolicyDecisionV1,
    grant: &EnforcementGrantV1,
    serial: u64,
) -> IsolationCommandV1 {
    IsolationCommandV1 {
        schema: ISOLATION_COMMAND_SCHEMA_V1.into(),
        command_id: format!("command.{serial}"),
        jti: format!("jti.command.{serial}"),
        enforcement_grant_jti: grant.jti.clone(),
        decision_id: decision.decision_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        actor: identity.actor.clone(),
        device: identity.device.clone(),
        workload: identity.workload.clone(),
        profile: identity.profile.clone(),
        proof_key_ref: identity.proof_key_ref.clone(),
        revocation_epoch: identity.revocation_epoch,
        binding: decision.binding.clone(),
        provider: decision.binding.audience.clone(),
        expected_resource_version: "incus-etag-7".into(),
        issued_at: "2026-07-29T00:01:30.000Z".into(),
        expires_at: "2026-07-29T00:02:30.000Z".into(),
        signed: signed(),
    }
}

pub fn receipt(command: &IsolationCommandV1, serial: u64) -> EnforcementReceiptV1 {
    EnforcementReceiptV1 {
        schema: ENFORCEMENT_RECEIPT_SCHEMA_V1.into(),
        receipt_id: format!("receipt.{serial}"),
        command_jti: command.jti.clone(),
        enforcement_grant_jti: command.enforcement_grant_jti.clone(),
        binding: command.binding.clone(),
        provider: command.provider.clone(),
        outcome: EnforcementOutcome::Applied,
        grant_consumed: true,
        applied_at: "2026-07-29T00:02:00.000Z".into(),
        resulting_resource_version: Some("incus-etag-8".into()),
        residual_exposures: Vec::new(),
        evidence_digest: digest(),
        signed: signed(),
    }
}
