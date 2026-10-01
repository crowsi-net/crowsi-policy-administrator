use crowsi_control_contracts::Validate;

use crate::{
    AdministratorError, ArtifactRole, KeyScope, PolicyAdministrator, ReservationInput, Result,
};

impl PolicyAdministrator {
    pub(crate) fn verify_revocation_evidence(
        &self,
        input: &ReservationInput<'_>,
        now: &str,
    ) -> Result<()> {
        let identity = input.identity;
        let snapshot = input.policy_information;
        identity
            .validate()
            .map_err(|error| AdministratorError::Contract(error.to_string()))?;
        snapshot
            .validate_at(now)
            .map_err(|error| AdministratorError::Contract(error.to_string()))?;
        self.trusted_keys.verify(
            ArtifactRole::Identity,
            &KeyScope::Identity {
                issuer: self.policy.identity_issuer.clone(),
                audience: self.policy.identity_audience.clone(),
            },
            identity,
            &identity.signed,
        )?;
        self.trusted_keys.verify(
            ArtifactRole::PolicyInformation,
            &KeyScope::Audience(self.policy.enforcement_audience.clone()),
            snapshot,
            &snapshot.signed,
        )?;
        if identity.issuer != self.policy.identity_issuer
            || identity.audience != self.policy.identity_audience
            || snapshot.identity_context_id != identity.context_id
            || snapshot.pairwise_subject != identity.pairwise_subject
            || snapshot.authoritative_revocation_epoch != identity.revocation_epoch
            || snapshot.policy_digest != self.policy.policy_digest
        {
            return Err(AdministratorError::Binding);
        }
        Ok(())
    }
}
