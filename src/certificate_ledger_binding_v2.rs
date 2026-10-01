use rusqlite::{Connection, TransactionBehavior, named_params};

use crate::{
    AdministratorError, CertificateAdministratorPolicyV2, Result,
    certificate_reservation_write_v2::to_i64,
};

#[allow(clippy::too_many_lines)]
pub(crate) fn pin(
    connection: &mut Connection,
    policy: &CertificateAdministratorPolicyV2,
) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT OR IGNORE INTO certificate_v2_ledger_binding VALUES (
           1, :domain, :deployment, :issuer, :audience, :provider, :policy_id,
           :policy_digest, :verifier_key, :revocation_issuer,
           :revocation_audience, :trust_revision
         )",
        named_params! {
            ":domain": policy.security_domain,
            ":deployment": policy.deployment_id,
            ":issuer": policy.authorization_issuer,
            ":audience": policy.authorization_audience,
            ":provider": policy.authorization_provider,
            ":policy_id": policy.authorization_policy_id,
            ":policy_digest": policy.authorization_policy_digest_sha256,
            ":verifier_key": policy.authorization_verifier_key_id,
            ":revocation_issuer": policy.revocation_issuer,
            ":revocation_audience": policy.revocation_audience,
            ":trust_revision": to_i64(policy.trust_revision)?,
        },
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO certificate_v2_approval_authority_binding
         VALUES (1, ?, ?, ?, ?, ?)",
        rusqlite::params![
            policy.approval_issuer,
            policy.approval_audience,
            policy.approval_relying_party_id,
            policy.approval_origin,
            policy.approval_challenge_authority_ref
        ],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO certificate_v2_signer_binding
         VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            policy.authorization_verifier_key_id,
            policy.authorization_signer_key_version,
            policy.authorization_signer_public_key_base64,
            policy.authorization_signer_public_key_digest_sha256,
            policy.authorization_signer_public_key_spki_sha256,
            policy.authorization_signer_workload,
            policy.authorization_signer_purpose
        ],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO certificate_v2_target_normalizer_binding
         VALUES (1, ?, ?)",
        [
            &policy.target_resource_normalizer_id,
            &policy.target_resource_normalizer_version,
        ],
    )?;
    let exact: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM certificate_v2_ledger_binding
          WHERE singleton = 1 AND security_domain = :domain
            AND deployment_id = :deployment
            AND authorization_issuer = :issuer
            AND authorization_audience = :audience
            AND authorization_provider = :provider
            AND authorization_policy_id = :policy_id
            AND authorization_policy_digest_sha256 = :policy_digest
            AND authorization_verifier_key_id = :verifier_key
            AND revocation_issuer = :revocation_issuer
            AND revocation_audience = :revocation_audience
            AND trust_revision = :trust_revision",
        named_params! {
            ":domain": policy.security_domain,
            ":deployment": policy.deployment_id,
            ":issuer": policy.authorization_issuer,
            ":audience": policy.authorization_audience,
            ":provider": policy.authorization_provider,
            ":policy_id": policy.authorization_policy_id,
            ":policy_digest": policy.authorization_policy_digest_sha256,
            ":verifier_key": policy.authorization_verifier_key_id,
            ":revocation_issuer": policy.revocation_issuer,
            ":revocation_audience": policy.revocation_audience,
            ":trust_revision": to_i64(policy.trust_revision)?,
        },
        |row| row.get(0),
    )?;
    if exact != 1 {
        return Err(AdministratorError::LedgerIntegrity);
    }
    let approval_exact: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM certificate_v2_approval_authority_binding
          WHERE singleton = 1 AND issuer = ? AND audience = ?
            AND relying_party_id = ? AND origin = ? AND challenge_authority_ref = ?",
        rusqlite::params![
            policy.approval_issuer,
            policy.approval_audience,
            policy.approval_relying_party_id,
            policy.approval_origin,
            policy.approval_challenge_authority_ref
        ],
        |row| row.get(0),
    )?;
    if approval_exact != 1 {
        return Err(AdministratorError::LedgerIntegrity);
    }
    let signer_exact: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM certificate_v2_signer_binding
          WHERE singleton = 1 AND key_id = ? AND key_version = ?
            AND public_key_base64 = ? AND public_key_digest_sha256 = ?
            AND public_key_spki_sha256 = ? AND workload = ? AND purpose = ?",
        rusqlite::params![
            policy.authorization_verifier_key_id,
            policy.authorization_signer_key_version,
            policy.authorization_signer_public_key_base64,
            policy.authorization_signer_public_key_digest_sha256,
            policy.authorization_signer_public_key_spki_sha256,
            policy.authorization_signer_workload,
            policy.authorization_signer_purpose
        ],
        |row| row.get(0),
    )?;
    if signer_exact != 1 {
        return Err(AdministratorError::LedgerIntegrity);
    }
    let normalizer_exact: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM certificate_v2_target_normalizer_binding
          WHERE singleton = 1 AND normalizer_id = ? AND normalizer_version = ?",
        [
            &policy.target_resource_normalizer_id,
            &policy.target_resource_normalizer_version,
        ],
        |row| row.get(0),
    )?;
    if normalizer_exact != 1 {
        return Err(AdministratorError::LedgerIntegrity);
    }
    crate::certificate_completion_binding_v2::pin(&transaction, policy)?;
    transaction.commit()?;
    Ok(())
}
