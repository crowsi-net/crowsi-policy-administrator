use crowsi_control_contracts::{
    CertificateExecutionCommandV2, CertificateExecutionGrantV2, CertificatePayloadV2,
    CertificatePolicyDecisionV2,
};
use rusqlite::{TransactionBehavior, params};

use crate::{
    AdministratorError, CertificateLeaseSignerIdentityV2, CertificatePolicyAdministratorV2, Result,
    certificate_execution_load_v2, certificate_policy_v2, certificate_signing_state_v2,
    clock_watermark,
};

pub(crate) fn prepare(
    administrator: &mut CertificatePolicyAdministratorV2,
    authorization_jti: &str,
    signer: &CertificateLeaseSignerIdentityV2,
) -> Result<certificate_signing_state_v2::PreparedSigning> {
    certificate_execution_load_v2::verify_signer(administrator, signer)?;
    if let Some(existing) =
        certificate_signing_state_v2::load_existing(administrator, authorization_jti, signer)?
    {
        return Ok(existing);
    }
    let transaction = administrator
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now = administrator.clock.now();
    let now_epoch_s = crate::clock::epoch_seconds(&now)?;
    clock_watermark::advance(&transaction, &now)?;
    let stored = certificate_execution_load_v2::load_reserved(&transaction, authorization_jti)?;
    let command: CertificateExecutionCommandV2 =
        certificate_execution_load_v2::closed_json(&stored.command_json)?;
    let decision: CertificatePolicyDecisionV2 =
        certificate_execution_load_v2::closed_json(&stored.decision_json)?;
    let grant: CertificateExecutionGrantV2 =
        certificate_execution_load_v2::closed_json(&stored.grant_json)?;
    certificate_policy_v2::verify_stored_chain(
        &administrator.policy,
        &administrator.trusted_keys,
        &decision,
        &grant,
        &command,
        now_epoch_s,
    )?;
    if command.jti != authorization_jti
        || command.certificate_digest_sha256() != stored.command_digest
        || u64::try_from(stored.expires_at_epoch_s).ok() != Some(command.expires_at_epoch_s)
    {
        return Err(AdministratorError::LedgerIntegrity);
    }
    certificate_execution_load_v2::verify_revocation(
        &transaction,
        &administrator.policy.revocation_issuer,
        &administrator.policy.security_domain,
        &command,
    )?;
    let lease = certificate_execution_load_v2::lease(command, &stored)?;
    let attempt_id = format!("signing:{}", lease.pa_reservation_id);
    let digest = lease.certificate_digest_sha256();
    let lease_json =
        serde_json::to_string(&lease).map_err(|_| AdministratorError::LedgerIntegrity)?;
    transaction.execute(
        "INSERT INTO certificate_v2_signing_handoffs(
           pa_reservation_id, authorization_jti, attempt_id, lease_digest_sha256,
           lease_json, signer_key_id, signer_key_version,
           signer_public_key_digest_sha256, signer_public_key_spki_sha256,
           signer_workload, signer_purpose, state, prepared_at_epoch_s
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?)",
        params![
            lease.pa_reservation_id,
            authorization_jti,
            attempt_id,
            digest,
            lease_json,
            signer.key_id,
            signer.key_version,
            signer.public_key_digest_sha256,
            signer.public_key_spki_sha256,
            signer.workload,
            signer.purpose,
            i64::try_from(now_epoch_s).map_err(|_| AdministratorError::Time)?
        ],
    )?;
    transaction.commit()?;
    Ok(certificate_signing_state_v2::prepared(
        attempt_id, digest, false, false,
    ))
}
