#![allow(dead_code)]

mod authorities;
mod chain;
mod contracts;
mod evaluation;
mod ledger;
mod signing;
mod snapshot;
mod trust;
mod v2;

use authorities::Authorities;
use crowsi_control_contracts::{
    ControlAction, CoverageAssertionV1, EnforcementGrantV1, EnforcementReceiptV1,
    IsolationCommandV1, PolicyDecisionV1, PolicyInformationSnapshotV1, RecoveryAuthorizationV1,
    SecurityIntentV1, VerifiedIdentityContextV1,
};
use crowsi_policy_administrator::{
    AdministratorPolicy, PolicyAdministrator, ReservationInput, Result, SimulationFixedClock,
};
use crowsi_policy_engine::{PolicyInput, evaluate};
#[allow(unused_imports)]
pub use ledger::TestLedger;
use signing::sign;
use std::path::Path;
#[allow(unused_imports)]
pub use v2::V2Fixture;

pub const FIXED_NOW: &str = "2026-07-29T00:02:00.000Z";

pub struct Fixture {
    pub authorities: Authorities,
    pub identity: VerifiedIdentityContextV1,
    pub intent: SecurityIntentV1,
    pub coverage: CoverageAssertionV1,
    pub policy_information: PolicyInformationSnapshotV1,
    pub decision: PolicyDecisionV1,
    pub grant: EnforcementGrantV1,
    pub command: IsolationCommandV1,
    pub recovery_authorization: Option<RecoveryAuthorizationV1>,
    pub policy_digest: String,
    pub serial: u64,
}

impl Fixture {
    pub fn new() -> Result<Self> {
        Self::version(1, 7, ControlAction::Quarantine)
    }

    pub fn restore() -> Result<Self> {
        Self::version(1, 7, ControlAction::Restore)
    }

    pub fn version(serial: u64, epoch: u64, action: ControlAction) -> Result<Self> {
        let authorities = Authorities::new()?;
        let policy_digest = policy_digest();
        let mut identity = contracts::identity(epoch, serial);
        let mut intent = contracts::intent(&identity, action, serial);
        let mut coverage = contracts::coverage(&intent.binding.resource, serial);
        sign(&authorities.identity, &mut identity)?;
        sign(&authorities.intent, &mut intent)?;
        sign(&authorities.coverage, &mut coverage)?;
        let mut policy_information =
            snapshot::snapshot(&identity, &intent, &coverage, &policy_digest, serial);
        sign(&authorities.policy_information, &mut policy_information)?;
        let result = evaluate(&evaluation::evaluation(
            &identity,
            &intent,
            &coverage,
            &policy_information,
        ));
        let mut decision = chain::decision(&identity, &intent, &result, serial);
        sign(&authorities.decision, &mut decision)?;
        let mut grant = chain::grant(&identity, &intent, &decision, serial);
        sign(&authorities.grant, &mut grant)?;
        let mut command = chain::command(&identity, &decision, &grant, serial);
        sign(&authorities.command, &mut command)?;
        let mut recovery_authorization = (action == ControlAction::Restore)
            .then(|| snapshot::recovery(&identity, &intent, &policy_information, serial));
        if let Some(recovery) = recovery_authorization.as_mut() {
            sign(&authorities.recovery, recovery)?;
        }
        Ok(Self {
            authorities,
            identity,
            intent,
            coverage,
            policy_information,
            decision,
            grant,
            command,
            recovery_authorization,
            policy_digest,
            serial,
        })
    }

    pub fn administrator(&self) -> Result<PolicyAdministrator> {
        self.administrator_at(FIXED_NOW)
    }

    pub fn administrator_at(&self, now: &str) -> Result<PolicyAdministrator> {
        PolicyAdministrator::in_memory_for_simulation(
            self.administrator_policy(),
            trust::trusted_keys(self)?,
            SimulationFixedClock::new(now)?,
        )
    }

    pub fn administrator_on_path_at(&self, path: &Path, now: &str) -> Result<PolicyAdministrator> {
        PolicyAdministrator::open_with_fixed_clock_for_simulation(
            path,
            self.administrator_policy(),
            trust::trusted_keys(self)?,
            SimulationFixedClock::new(now)?,
        )
    }

    pub fn reservation(&self, expected: u64, next: u64) -> ReservationInput<'_> {
        ReservationInput {
            identity: &self.identity,
            intent: &self.intent,
            coverage: &self.coverage,
            policy_information: &self.policy_information,
            decision: &self.decision,
            grant: &self.grant,
            command: &self.command,
            recovery_authorization: self.recovery_authorization.as_ref(),
            expected_isolation_epoch: expected,
            next_isolation_epoch: next,
        }
    }

    pub fn receipt(&self) -> Result<EnforcementReceiptV1> {
        let mut receipt = chain::receipt(&self.command, self.serial);
        sign(&self.authorities.receipt, &mut receipt)?;
        Ok(receipt)
    }

    fn administrator_policy(&self) -> AdministratorPolicy {
        AdministratorPolicy {
            security_domain: "customer-hat".into(),
            deployment_id: "deployment.production.1".into(),
            identity_issuer: self.identity.issuer.clone(),
            identity_audience: self.identity.audience.clone(),
            enforcement_audience: self.command.provider.clone(),
            policy_digest: self.policy_digest.clone(),
            max_risk_score: 90,
            step_up_risk_score: 70,
        }
    }
}

fn policy_digest() -> String {
    PolicyInput {
        digest: "",
        max_risk_score: 90,
        step_up_risk_score: 70,
    }
    .computed_digest()
}
