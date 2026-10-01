use crowsi_control_contracts::{
    CoverageAssertionV1, EnforcementGrantV1, IsolationCommandV1, PolicyDecisionV1,
    PolicyInformationSnapshotV1, RecoveryAuthorizationV1, SecurityIntentV1,
    VerifiedIdentityContextV1,
};

#[derive(Clone, Debug)]
pub struct AdministratorPolicy {
    pub security_domain: String,
    pub deployment_id: String,
    pub identity_issuer: String,
    pub identity_audience: String,
    pub enforcement_audience: String,
    pub policy_digest: String,
    pub max_risk_score: u8,
    pub step_up_risk_score: u8,
}

pub struct ReservationInput<'a> {
    pub identity: &'a VerifiedIdentityContextV1,
    pub intent: &'a SecurityIntentV1,
    pub coverage: &'a CoverageAssertionV1,
    pub policy_information: &'a PolicyInformationSnapshotV1,
    pub decision: &'a PolicyDecisionV1,
    pub grant: &'a EnforcementGrantV1,
    pub command: &'a IsolationCommandV1,
    pub recovery_authorization: Option<&'a RecoveryAuthorizationV1>,
    pub expected_isolation_epoch: u64,
    pub next_isolation_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementReservation {
    pub command_jti: String,
    pub grant_jti: String,
    pub resource: String,
    pub isolation_epoch: u64,
    pub command_digest: String,
    pub expected_resource_version: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementStatus {
    pub resource: String,
    pub isolation_epoch: u64,
    pub command_jti: String,
    pub state: String,
    pub outcome: Option<String>,
}
