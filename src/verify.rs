use crowsi_control_contracts::{
    CanonicalPayloadV1, ControlAction, DecisionEffect, validate_authorization_chain,
};

use crate::{
    AdministratorError, ArtifactRole, KeyScope, PolicyAdministrator, ReservationInput, Result,
    policy_input::evaluate_snapshot,
};

impl PolicyAdministrator {
    pub(crate) fn verify_evidence(&self, input: &ReservationInput<'_>, now: &str) -> Result<()> {
        self.verify_signatures(input)?;
        validate_authorization_chain(
            input.identity,
            input.intent,
            input.decision,
            input.grant,
            input.command,
            input.policy_information.authoritative_revocation_epoch,
            now,
        )
        .map_err(contract)?;
        input.coverage.validate_at(now).map_err(contract)?;
        input
            .policy_information
            .validate_at(now)
            .map_err(contract)?;
        self.verify_snapshot_binding(input)?;
        self.verify_recovery(input, now)
    }

    fn verify_snapshot_binding(&self, input: &ReservationInput<'_>) -> Result<()> {
        let snapshot = input.policy_information;
        let identity = input.identity;
        if identity.issuer != self.policy.identity_issuer
            || identity.audience != self.policy.identity_audience
            || input.command.binding.audience != self.policy.enforcement_audience
            || snapshot.identity_context_id != identity.context_id
            || snapshot.pairwise_subject != identity.pairwise_subject
            || snapshot.device_posture.target != identity.device
            || snapshot.workload_posture.target != identity.workload
            || snapshot.coverage_assertion_id != input.coverage.assertion_id
            || snapshot.coverage_digest != input.coverage.payload_digest()
            || snapshot.policy_digest != self.policy.policy_digest
            || snapshot.management_authority.binding != input.intent.binding
        {
            return Err(AdministratorError::Binding);
        }
        Ok(())
    }

    fn verify_recovery(&self, input: &ReservationInput<'_>, now: &str) -> Result<()> {
        let Some(recovery) = input.recovery_authorization else {
            return if input.command.binding.action == ControlAction::Restore {
                Err(AdministratorError::Trust)
            } else {
                Ok(())
            };
        };
        if input.command.binding.action != ControlAction::Restore {
            return Err(AdministratorError::Binding);
        }
        recovery.validate_at(now).map_err(contract)?;
        self.trusted_keys.verify(
            ArtifactRole::RecoveryAuthorization,
            &KeyScope::Audience(self.policy.enforcement_audience.clone()),
            recovery,
            &recovery.signed,
        )?;
        let snapshot = input.policy_information;
        if recovery.identity_context_id != input.identity.context_id
            || recovery.pairwise_subject != input.identity.pairwise_subject
            || recovery.binding != input.command.binding
            || recovery.incident_id != snapshot.incident.incident_id
            || recovery.policy_snapshot_id != snapshot.snapshot_id
            || recovery.policy_snapshot_digest != snapshot.payload_digest()
            || recovery.authoritative_revocation_epoch != snapshot.authoritative_revocation_epoch
        {
            return Err(AdministratorError::Binding);
        }
        Ok(())
    }

    pub(crate) fn verify_policy(&self, input: &ReservationInput<'_>, now: &str) -> Result<()> {
        let evaluation = evaluate_snapshot(input, &self.policy, now);
        if evaluation.effect != DecisionEffect::Permit {
            return Err(AdministratorError::PolicyDenied);
        }
        if input.decision.effect != evaluation.effect
            || input.decision.required_assurance != evaluation.required_assurance
            || input.decision.policy_digest != evaluation.policy_digest
        {
            return Err(AdministratorError::Binding);
        }
        Ok(())
    }
}

fn contract(error: impl std::fmt::Display) -> AdministratorError {
    AdministratorError::Contract(error.to_string())
}
