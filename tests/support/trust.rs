use crowsi_policy_administrator::{ArtifactRole, KeyScope, Result, TrustedKeys};

use super::Fixture;

pub fn trusted_keys(fixture: &Fixture) -> Result<TrustedKeys> {
    let mut keys = TrustedKeys::default();
    let authorities = &fixture.authorities;
    insert(
        &mut keys,
        "identity.control.1",
        ArtifactRole::Identity,
        KeyScope::Identity {
            issuer: fixture.identity.issuer.clone(),
            audience: fixture.identity.audience.clone(),
        },
        authorities.identity.verifying_key(),
    )?;
    insert(
        &mut keys,
        "intent.control.1",
        ArtifactRole::Intent,
        KeyScope::ProofKey(fixture.identity.proof_key_ref.clone()),
        authorities.intent.verifying_key(),
    )?;
    for (key_id, role, bytes) in [
        (
            "decision.control.1",
            ArtifactRole::PolicyDecision,
            authorities.decision.verifying_key(),
        ),
        (
            "grant.control.1",
            ArtifactRole::EnforcementGrant,
            authorities.grant.verifying_key(),
        ),
    ] {
        insert(
            &mut keys,
            key_id,
            role,
            KeyScope::Policy(fixture.policy_digest.clone()),
            bytes,
        )?;
    }
    for (key_id, role, bytes) in [
        (
            "command.control.1",
            ArtifactRole::IsolationCommand,
            authorities.command.verifying_key(),
        ),
        (
            "policy-information.control.1",
            ArtifactRole::PolicyInformation,
            authorities.policy_information.verifying_key(),
        ),
        (
            "recovery.control.1",
            ArtifactRole::RecoveryAuthorization,
            authorities.recovery.verifying_key(),
        ),
    ] {
        insert(
            &mut keys,
            key_id,
            role,
            KeyScope::Audience(fixture.command.provider.clone()),
            bytes,
        )?;
    }
    insert(
        &mut keys,
        "coverage.control.1",
        ArtifactRole::Coverage,
        KeyScope::Observer(fixture.coverage.observer_id.clone()),
        authorities.coverage.verifying_key(),
    )?;
    insert(
        &mut keys,
        "receipt.control.1",
        ArtifactRole::Receipt,
        KeyScope::Provider(fixture.command.provider.clone()),
        authorities.receipt.verifying_key(),
    )?;
    Ok(keys)
}

fn insert(
    keys: &mut TrustedKeys,
    key_id: &str,
    role: ArtifactRole,
    scope: KeyScope,
    bytes: [u8; 32],
) -> Result<()> {
    keys.insert_ed25519(key_id, role, scope, bytes)
}
