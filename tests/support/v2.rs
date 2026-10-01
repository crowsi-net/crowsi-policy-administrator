use crowsi_control_contracts::{
    ENFORCEMENT_RECEIPT_SCHEMA_V2, EnforcementOutcome, EnforcementReceiptV2,
    ISOLATION_COMMAND_SCHEMA_V2, IsolationCommandV2,
};
use crowsi_policy_administrator::{ReservationInputV2, Result};

use super::{Fixture, contracts::digest, signing::sign};

pub struct V2Fixture {
    pub base: Fixture,
    pub command: IsolationCommandV2,
}

impl V2Fixture {
    pub fn new() -> Result<Self> {
        Self::version(1, 0, 1)
    }

    pub fn version(serial: u64, previous_fence: u64, fence: u64) -> Result<Self> {
        let base = Fixture::version(
            serial,
            7,
            crowsi_control_contracts::ControlAction::Quarantine,
        )?;
        let mut command = IsolationCommandV2 {
            schema: ISOLATION_COMMAND_SCHEMA_V2.into(),
            command_id: format!("command.v2.{serial}"),
            jti: format!("jti.command.v2.{serial}"),
            security_domain: "customer-hat".into(),
            deployment_id: "deployment.production.1".into(),
            incident_id: base.policy_information.incident.incident_id.clone(),
            target_id: base.intent.binding.resource.clone(),
            release_id: format!("release.{serial}"),
            release_digest: repeated_digest(serial, 'b'),
            checkpoint_id: format!("checkpoint.{serial}"),
            checkpoint_digest: repeated_digest(serial, 'c'),
            checkpoint_sequence: serial,
            release_reservation_id: format!("release-reservation.{serial}"),
            enforcement_grant_jti: base.grant.jti.clone(),
            decision_id: base.decision.decision_id.clone(),
            pairwise_subject: base.identity.pairwise_subject.clone(),
            actor: base.identity.actor.clone(),
            device: base.identity.device.clone(),
            workload: base.identity.workload.clone(),
            profile: base.identity.profile.clone(),
            proof_key_ref: base.identity.proof_key_ref.clone(),
            revocation_epoch: base.identity.revocation_epoch,
            binding: base.decision.binding.clone(),
            provider: base.command.provider.clone(),
            previous_fence_epoch: previous_fence,
            fence_epoch: fence,
            expected_resource_version: format!("incus-etag-{}", 7 + previous_fence),
            issued_at: "2026-07-29T00:01:30.000Z".into(),
            expires_at: "2026-07-29T00:02:30.000Z".into(),
            signed: super::contracts::signed(),
        };
        sign(&base.authorities.command, &mut command)?;
        Ok(Self { base, command })
    }

    pub fn reservation(&self) -> ReservationInputV2<'_> {
        self.reservation_with(&self.command)
    }

    pub fn reservation_with<'a>(
        &'a self,
        command: &'a IsolationCommandV2,
    ) -> ReservationInputV2<'a> {
        ReservationInputV2 {
            identity: &self.base.identity,
            intent: &self.base.intent,
            coverage: &self.base.coverage,
            policy_information: &self.base.policy_information,
            decision: &self.base.decision,
            grant: &self.base.grant,
            command,
            recovery_authorization: self.base.recovery_authorization.as_ref(),
        }
    }

    pub fn receipt(&self) -> Result<EnforcementReceiptV2> {
        let mut receipt = EnforcementReceiptV2 {
            schema: ENFORCEMENT_RECEIPT_SCHEMA_V2.into(),
            receipt_id: format!("receipt.v2.{}", self.base.serial),
            command_jti: self.command.jti.clone(),
            command_digest: self.command.signed.digest.clone(),
            security_domain: self.command.security_domain.clone(),
            deployment_id: self.command.deployment_id.clone(),
            incident_id: self.command.incident_id.clone(),
            target_id: self.command.target_id.clone(),
            release_reservation_id: self.command.release_reservation_id.clone(),
            fence_epoch: self.command.fence_epoch,
            binding: self.command.binding.clone(),
            provider: self.command.provider.clone(),
            outcome: EnforcementOutcome::Applied,
            authorization_consumed: true,
            applied_at: "2026-07-29T00:02:00.000Z".into(),
            expected_resource_version: self.command.expected_resource_version.clone(),
            resulting_resource_version: Some(format!(
                "incus-etag-{}",
                7 + self.command.fence_epoch
            )),
            residual_exposures: Vec::new(),
            evidence_digest: digest(),
            signed: super::contracts::signed(),
        };
        sign(&self.base.authorities.receipt, &mut receipt)?;
        Ok(receipt)
    }

    pub fn administrator(&self) -> Result<crowsi_policy_administrator::PolicyAdministrator> {
        self.base.administrator()
    }
}

fn repeated_digest(serial: u64, fallback: char) -> String {
    let value = char::from_digit((serial % 10) as u32, 10).unwrap_or(fallback);
    format!("sha256:{}", value.to_string().repeat(64))
}
