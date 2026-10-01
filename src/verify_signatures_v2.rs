use crate::{ArtifactRole, KeyScope, PolicyAdministrator, ReservationInputV2, Result};

impl PolicyAdministrator {
    pub(crate) fn verify_signatures_v2(&self, input: &ReservationInputV2<'_>) -> Result<()> {
        let policy = KeyScope::Policy(self.policy.policy_digest.clone());
        let audience = KeyScope::Audience(self.policy.enforcement_audience.clone());
        let identity = KeyScope::Identity {
            issuer: self.policy.identity_issuer.clone(),
            audience: self.policy.identity_audience.clone(),
        };
        for result in [
            self.trusted_keys.verify(
                ArtifactRole::Identity,
                &identity,
                input.identity,
                &input.identity.signed,
            ),
            self.trusted_keys.verify(
                ArtifactRole::Intent,
                &KeyScope::ProofKey(input.identity.proof_key_ref.clone()),
                input.intent,
                &input.intent.signed,
            ),
            self.trusted_keys.verify(
                ArtifactRole::PolicyDecision,
                &policy,
                input.decision,
                &input.decision.signed,
            ),
            self.trusted_keys.verify(
                ArtifactRole::EnforcementGrant,
                &policy,
                input.grant,
                &input.grant.signed,
            ),
            self.trusted_keys.verify(
                ArtifactRole::IsolationCommand,
                &audience,
                input.command,
                &input.command.signed,
            ),
            self.trusted_keys.verify(
                ArtifactRole::Coverage,
                &KeyScope::Observer(input.coverage.observer_id.clone()),
                input.coverage,
                &input.coverage.signed,
            ),
            self.trusted_keys.verify(
                ArtifactRole::PolicyInformation,
                &audience,
                input.policy_information,
                &input.policy_information.signed,
            ),
        ] {
            result?;
        }
        Ok(())
    }
}
