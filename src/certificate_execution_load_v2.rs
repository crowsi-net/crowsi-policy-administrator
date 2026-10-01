use crowsi_control_contracts::{
    CERTIFICATE_EXECUTION_LEASE_SCHEMA_V2, CertificateExecutionCommandV2,
    CertificateExecutionLeaseV2, Validate,
};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::{
    AdministratorError, CertificateLeaseSignerIdentityV2, CertificatePolicyAdministratorV2, Result,
};

pub(crate) struct StoredReservation {
    pub(crate) command_json: String,
    pub(crate) decision_json: String,
    pub(crate) grant_json: String,
    pub(crate) command_digest: String,
    pub(crate) reserved_at_epoch_s: i64,
    pub(crate) expires_at_epoch_s: i64,
}

pub(crate) fn load_reserved(tx: &Transaction<'_>, jti: &str) -> Result<StoredReservation> {
    tx.query_row(
        "SELECT command_json, decision_json, grant_json,
                authorization_command_digest_sha256, reserved_at_epoch_s,
                expires_at_epoch_s
           FROM certificate_v2_reservations
          WHERE authorization_jti = ? AND state = 'reserved'
            AND lease_digest_sha256 IS NULL",
        [jti],
        |row| {
            Ok(StoredReservation {
                command_json: row.get(0)?,
                decision_json: row.get(1)?,
                grant_json: row.get(2)?,
                command_digest: row.get(3)?,
                reserved_at_epoch_s: row.get(4)?,
                expires_at_epoch_s: row.get(5)?,
            })
        },
    )
    .optional()?
    .ok_or(AdministratorError::Replay)
}

pub(crate) fn closed_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| AdministratorError::LedgerIntegrity)
}

pub(crate) fn lease(
    command: CertificateExecutionCommandV2,
    stored: &StoredReservation,
) -> Result<CertificateExecutionLeaseV2> {
    let lease = CertificateExecutionLeaseV2 {
        schema: CERTIFICATE_EXECUTION_LEASE_SCHEMA_V2.into(),
        pa_reservation_id: command.pa_reservation_id.clone(),
        authorization_command_digest_sha256: stored.command_digest.clone(),
        reserved_at_epoch_s: u64::try_from(stored.reserved_at_epoch_s)
            .map_err(|_| AdministratorError::LedgerIntegrity)?,
        command,
        one_use: true,
    };
    lease
        .validate()
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    Ok(lease)
}

pub(crate) fn verify_revocation(
    tx: &Transaction<'_>,
    revocation_issuer: &str,
    security_domain: &str,
    command: &CertificateExecutionCommandV2,
) -> Result<()> {
    let current = tx
        .query_row(
            "SELECT epoch FROM certificate_v2_revocation_epochs
              WHERE revocation_issuer = ? AND security_domain = ?
                AND pairwise_subject = ?",
            params![
                revocation_issuer,
                security_domain,
                command.binding.identity.pairwise_subject
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(AdministratorError::Revoked)?;
    if u64::try_from(current).ok() == Some(command.binding.identity.identity_revocation_epoch) {
        Ok(())
    } else {
        Err(AdministratorError::Revoked)
    }
}

pub(crate) fn verify_signer(
    administrator: &CertificatePolicyAdministratorV2,
    signer: &CertificateLeaseSignerIdentityV2,
) -> Result<()> {
    let policy = &administrator.policy;
    let exact = signer.key_id == policy.authorization_verifier_key_id
        && signer.key_version == policy.authorization_signer_key_version
        && signer.public_key_digest_sha256 == policy.authorization_signer_public_key_digest_sha256
        && signer.public_key_spki_sha256 == policy.authorization_signer_public_key_spki_sha256
        && signer.workload == policy.authorization_signer_workload
        && signer.purpose == policy.authorization_signer_purpose;
    exact
        .then_some(())
        .ok_or(AdministratorError::CertificateAuthorizationUnavailable)
}
