use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{Validate, validate_certificate_authorization_chain_v2};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::{AdministratorError, CertificateAdministratorPolicyV2, Result};

pub(crate) fn validate_policy_config(value: &CertificateAdministratorPolicyV2) -> Result<()> {
    let identifiers = [
        &value.security_domain,
        &value.deployment_id,
        &value.authorization_issuer,
        &value.authorization_audience,
        &value.authorization_provider,
        &value.authorization_policy_id,
        &value.authorization_verifier_key_id,
        &value.authorization_signer_workload,
        &value.authorization_signer_purpose,
        &value.authorization_channel,
        &value.target_resource_normalizer_id,
        &value.target_resource_normalizer_version,
        &value.approval_issuer,
        &value.approval_audience,
        &value.approval_relying_party_id,
        &value.approval_origin,
        &value.approval_challenge_authority_ref,
        &value.authority_outcome_issuer,
        &value.authority_outcome_audience,
        &value.certificate_authority_id,
        &value.authority_receipt_key_id,
        &value.authority_receipt_key_version,
        &value.authority_receipt_key_purpose,
        &value.manager_commit_issuer,
        &value.manager_commit_audience,
        &value.manager_commit_workload,
        &value.manager_commit_key_id,
        &value.manager_commit_key_version,
        &value.manager_commit_key_purpose,
        &value.manager_handoff_issuer,
        &value.manager_handoff_audience,
        &value.manager_handoff_workload,
        &value.manager_handoff_key_id,
        &value.manager_handoff_key_version,
        &value.manager_handoff_key_purpose,
        &value.revocation_issuer,
        &value.revocation_audience,
    ];
    let ids_valid = identifiers.into_iter().all(|item| {
        (8..=256).contains(&item.len())
            && item.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
            })
    });
    let digest_valid = [
        &value.authorization_policy_digest_sha256,
        &value.authority_receipt_public_key_spki_sha256,
        &value.manager_commit_public_key_spki_sha256,
        &value.manager_handoff_public_key_spki_sha256,
    ]
    .into_iter()
    .all(|value| valid_digest(value));
    let bounded = (1..=120).contains(&value.max_authorization_ttl_seconds)
        && (1..=60).contains(&value.max_revocation_snapshot_age_seconds)
        && (60..=86_400).contains(&value.max_completion_recovery_seconds)
        && (8..=160).contains(&value.authorization_signer_key_version.len())
        && value.authorization_signer_purpose == "certificate-execution-authorization"
        && value.authority_receipt_key_purpose == "certificate-authority-receipt"
        && value.manager_commit_key_purpose == "certificate-manager-commit-receipt"
        && value.manager_handoff_key_purpose == "certificate-manager-handoff-receipt"
        && value.trust_revision > 0;
    if ids_valid && digest_valid && bounded && valid_signer_key(value) {
        Ok(())
    } else {
        Err(AdministratorError::Trust)
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_signer_key(value: &CertificateAdministratorPolicyV2) -> bool {
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(&value.authorization_signer_public_key_base64) else {
        return false;
    };
    let Ok(bytes) = <[u8; 32]>::try_from(decoded.as_slice()) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&bytes) else {
        return false;
    };
    let digest = format!("{:x}", Sha256::digest(bytes));
    let spki_digest = ed25519_spki_digest(&bytes);
    !key.is_weak()
        && URL_SAFE_NO_PAD.encode(bytes) == value.authorization_signer_public_key_base64
        && digest == value.authorization_signer_public_key_digest_sha256
        && spki_digest == value.authorization_signer_public_key_spki_sha256
}

fn ed25519_spki_digest(key: &[u8; 32]) -> String {
    const PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut der = Vec::with_capacity(PREFIX.len() + key.len());
    der.extend_from_slice(&PREFIX);
    der.extend_from_slice(key);
    format!("{:x}", Sha256::digest(der))
}

pub(crate) fn revalidate_freshness(
    input: &crate::CertificateReservationInputV2<'_>,
    policy: &CertificateAdministratorPolicyV2,
    now_epoch_s: u64,
) -> Result<()> {
    validate_certificate_authorization_chain_v2(
        input.decision,
        input.grant,
        input.command,
        now_epoch_s,
    )
    .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    if let Some(approval) = input.approval_evidence {
        approval
            .validate()
            .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    }
    input
        .revocation_evidence
        .validate()
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    if let Some(approval) = input.approval_evidence
        && (approval.issued_at_epoch_s > now_epoch_s || now_epoch_s >= approval.expires_at_epoch_s)
    {
        return Err(AdministratorError::Time);
    }
    let evidence = input.revocation_evidence;
    if evidence.verified_at_epoch_s > now_epoch_s
        || now_epoch_s.saturating_sub(evidence.verified_at_epoch_s)
            > policy.max_revocation_snapshot_age_seconds
    {
        Err(AdministratorError::Revoked)
    } else {
        Ok(())
    }
}
