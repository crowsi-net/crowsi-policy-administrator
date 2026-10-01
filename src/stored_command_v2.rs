use crowsi_control_contracts::{CanonicalPayloadV1, IsolationCommandV2, Validate};

use crate::{AdministratorError, AdministratorPolicy, ArtifactRole, KeyScope, Result, TrustedKeys};

pub(crate) fn verify(
    policy: &AdministratorPolicy,
    trusted_keys: &TrustedKeys,
    command: &IsolationCommandV2,
    stored_digest: &str,
) -> Result<()> {
    command
        .validate()
        .map_err(|_| AdministratorError::LedgerIntegrity)?;
    if command.payload_digest() != stored_digest
        || command.security_domain != policy.security_domain
        || command.deployment_id != policy.deployment_id
        || command.provider != policy.enforcement_audience
    {
        return Err(AdministratorError::LedgerIntegrity);
    }
    trusted_keys.verify(
        ArtifactRole::IsolationCommand,
        &KeyScope::Audience(policy.enforcement_audience.clone()),
        command,
        &command.signed,
    )
}
