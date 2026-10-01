use crowsi_control_contracts::{
    CoverageAssertionV1, EnforcementGrantV1, IsolationCommandV2, PolicyDecisionV1,
    PolicyInformationSnapshotV1, RecoveryAuthorizationV1, SecurityIntentV1,
    VerifiedIdentityContextV1,
};

pub struct ReservationInputV2<'a> {
    pub identity: &'a VerifiedIdentityContextV1,
    pub intent: &'a SecurityIntentV1,
    pub coverage: &'a CoverageAssertionV1,
    pub policy_information: &'a PolicyInformationSnapshotV1,
    pub decision: &'a PolicyDecisionV1,
    pub grant: &'a EnforcementGrantV1,
    pub command: &'a IsolationCommandV2,
    pub recovery_authorization: Option<&'a RecoveryAuthorizationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementReservationV2 {
    pub command_jti: String,
    pub release_reservation_id: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub target_id: String,
    pub fence_epoch: u64,
    pub command_digest: String,
    pub expected_resource_version: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementStatusV2 {
    pub command_jti: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub target_id: String,
    pub fence_epoch: u64,
    pub state: String,
    pub outcome: Option<String>,
}
