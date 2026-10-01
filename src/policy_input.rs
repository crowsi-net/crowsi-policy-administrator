use crowsi_control_contracts::{PolicyAuthorityState, PolicyIncidentState, PolicyPostureState};
use crowsi_policy_engine::{
    AuthorityState, EvaluationInput, IncidentInput, IncidentState, ManagementAuthorityInput,
    PipInput, PolicyEvaluation, PolicyInput, PostureInput, PostureState, TrustWindow, evaluate,
};

use crate::{AdministratorPolicy, ReservationInput};

pub(crate) fn evaluate_snapshot(
    input: &ReservationInput<'_>,
    policy: &AdministratorPolicy,
    now: &str,
) -> PolicyEvaluation {
    let snapshot = input.policy_information;
    let authority = &snapshot.management_authority;
    let evaluation = EvaluationInput {
        identity: input.identity,
        intent: input.intent,
        pip: PipInput {
            current_revocation_epoch: snapshot.authoritative_revocation_epoch,
            device_posture: posture(&snapshot.device_posture),
            workload_posture: posture(&snapshot.workload_posture),
            coverage: input.coverage,
            incident: IncidentInput {
                incident_id: &snapshot.incident.incident_id,
                resource: &snapshot.incident.resource,
                state: incident_state(snapshot.incident.state),
                window: window(
                    &snapshot.incident.observed_at,
                    &snapshot.incident.valid_until,
                ),
            },
            management_authority: ManagementAuthorityInput {
                state: authority_state(authority.state),
                identity_context_id: &authority.identity_context_id,
                authorization_grant_id: &authority.authorization_grant_id,
                revocation_epoch: authority.revocation_epoch,
                audience: &authority.binding.audience,
                resource: &authority.binding.resource,
                action: authority.binding.action,
                purpose: &authority.binding.purpose,
                channel: authority.binding.channel,
                window: window(&authority.observed_at, &authority.valid_until),
            },
            policy: PolicyInput {
                digest: &policy.policy_digest,
                max_risk_score: policy.max_risk_score,
                step_up_risk_score: policy.step_up_risk_score,
            },
            now,
            risk_score: snapshot.risk_score,
        },
    };
    evaluate(&evaluation)
}

fn posture(value: &crowsi_control_contracts::PostureAssertionV1) -> PostureInput<'_> {
    PostureInput {
        target: &value.target,
        state: match value.state {
            PolicyPostureState::Trusted => PostureState::Trusted,
            PolicyPostureState::Untrusted => PostureState::Untrusted,
            PolicyPostureState::Unknown => PostureState::Unknown,
        },
        window: window(&value.observed_at, &value.valid_until),
    }
}

const fn window<'a>(observed_at: &'a str, valid_until: &'a str) -> TrustWindow<'a> {
    TrustWindow {
        observed_at,
        valid_until,
    }
}

const fn authority_state(value: PolicyAuthorityState) -> AuthorityState {
    match value {
        PolicyAuthorityState::Authorized => AuthorityState::Authorized,
        PolicyAuthorityState::Denied => AuthorityState::Denied,
        PolicyAuthorityState::Unknown => AuthorityState::Unknown,
    }
}

const fn incident_state(value: PolicyIncidentState) -> IncidentState {
    match value {
        PolicyIncidentState::Normal => IncidentState::Normal,
        PolicyIncidentState::Detected => IncidentState::Detected,
        PolicyIncidentState::ContainmentRequested => IncidentState::ContainmentRequested,
        PolicyIncidentState::Contained => IncidentState::Contained,
        PolicyIncidentState::RecoveryPending => IncidentState::RecoveryPending,
        PolicyIncidentState::RecoveryAuthorized => IncidentState::RecoveryAuthorized,
        PolicyIncidentState::Restoring => IncidentState::Restoring,
        PolicyIncidentState::Monitoring => IncidentState::Monitoring,
        PolicyIncidentState::Closed => IncidentState::Closed,
        PolicyIncidentState::Unknown => IncidentState::Unknown,
    }
}
