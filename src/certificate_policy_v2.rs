use crowsi_control_contracts::{
    CertificateExecutionCommandV2, CertificateExecutionGrantV2, CertificatePayloadV2,
    CertificatePolicyDecisionV2, Validate, validate_certificate_authorization_chain_v2,
};

use crate::{
    AdministratorError, ArtifactRole, CertificatePolicyAdministratorV2,
    CertificateReservationInputV2, KeyScope, Result, certificate_approval_policy_v2,
};

impl CertificatePolicyAdministratorV2 {
    pub(crate) fn verify_reservation(
        &self,
        input: &CertificateReservationInputV2<'_>,
        now_epoch_s: u64,
    ) -> Result<()> {
        verify_stored_chain(
            &self.policy,
            &self.trusted_keys,
            input.decision,
            input.grant,
            input.command,
            now_epoch_s,
        )?;
        certificate_approval_policy_v2::verify(self, input, now_epoch_s)?;
        self.verify_revocation_evidence(input, now_epoch_s)
    }

    fn verify_revocation_evidence(
        &self,
        input: &CertificateReservationInputV2<'_>,
        now_epoch_s: u64,
    ) -> Result<()> {
        let evidence = input.revocation_evidence;
        evidence
            .validate()
            .map_err(|error| AdministratorError::Contract(error.to_string()))?;
        let binding = &input.command.binding;
        let revocation = &binding.revocation;
        let exact = evidence.issuer == self.policy.revocation_issuer
            && evidence.audience == self.policy.revocation_audience
            && evidence.pairwise_subject == binding.identity.pairwise_subject
            && evidence.previous_identity_revocation_epoch
                == revocation.previous_identity_revocation_epoch
            && evidence.identity_revocation_epoch == revocation.snapshot_epoch
            && evidence.verified_at_epoch_s == revocation.snapshot_verified_at_epoch_s
            && evidence.authoritative == revocation.authoritative
            && evidence.snapshot_id == revocation.snapshot_id
            && evidence.certificate_digest_sha256() == revocation.snapshot_digest_sha256
            && now_epoch_s.saturating_sub(evidence.verified_at_epoch_s)
                <= self.policy.max_revocation_snapshot_age_seconds;
        if !exact {
            return Err(AdministratorError::Revoked);
        }
        self.trusted_keys.verify_certificate(
            ArtifactRole::CertificateRevocationEvidence,
            &KeyScope::Revocation {
                issuer: evidence.issuer.clone(),
                audience: evidence.audience.clone(),
            },
            evidence,
            &evidence.signed,
        )
    }
}

pub(crate) fn verify_stored_chain(
    policy: &crate::CertificateAdministratorPolicyV2,
    trusted_keys: &crate::TrustedKeys,
    decision: &CertificatePolicyDecisionV2,
    grant: &CertificateExecutionGrantV2,
    command: &CertificateExecutionCommandV2,
    now_epoch_s: u64,
) -> Result<()> {
    validate_certificate_authorization_chain_v2(decision, grant, command, now_epoch_s)
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    let binding = &command.binding;
    let deployment = &binding.deployment;
    let exact = deployment.security_domain == policy.security_domain
        && deployment.deployment_id == policy.deployment_id
        && deployment.trust_revision == policy.trust_revision
        && binding.issuer == policy.authorization_issuer
        && binding.audience == policy.authorization_audience
        && binding.channel == policy.authorization_channel
        && binding.policy_id == policy.authorization_policy_id
        && binding.policy_digest_sha256 == policy.authorization_policy_digest_sha256
        && binding.target.provider == policy.authorization_provider
        && binding.target.target_resource_normalizer_id == policy.target_resource_normalizer_id
        && binding.target.target_resource_normalizer_version
            == policy.target_resource_normalizer_version
        && command.signature_key_id == policy.authorization_verifier_key_id
        && command.signature_key_version == policy.authorization_signer_key_version
        && command.signature_public_key_spki_sha256
            == policy.authorization_signer_public_key_spki_sha256
        && command.signature_key_purpose == policy.authorization_signer_purpose
        && command.signature_algorithm == policy.authorization_signature_algorithm
        && command.expires_at_epoch_s - command.issued_at_epoch_s
            <= policy.max_authorization_ttl_seconds
        && now_epoch_s.saturating_sub(binding.revocation.snapshot_verified_at_epoch_s)
            <= policy.max_revocation_snapshot_age_seconds;
    if !exact || decision.signed.key_id == grant.signed.key_id {
        return Err(AdministratorError::Binding);
    }
    let scope = KeyScope::Policy(binding.policy_id.clone());
    trusted_keys.verify_certificate(
        ArtifactRole::CertificatePolicyDecision,
        &scope,
        decision,
        &decision.signed,
    )?;
    trusted_keys.verify_certificate(
        ArtifactRole::CertificateExecutionGrant,
        &scope,
        grant,
        &grant.signed,
    )
}
