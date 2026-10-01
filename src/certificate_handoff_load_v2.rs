use crowsi_control_contracts::{
    CertificateExecutionCommandV2, CertificateExecutionLeaseV2, CertificatePayloadV2,
    SignedCertificateExecutionAuthorizationV2, Validate,
};
use rusqlite::{OptionalExtension, Transaction};

use crate::{AdministratorError, Result, certificate_release_v2};

pub(crate) struct PendingHandoff {
    pub(crate) lease: CertificateExecutionLeaseV2,
    pub(crate) lease_digest_sha256: String,
    pub(crate) command_expires_at_epoch_s: u64,
}

pub(crate) fn load(
    tx: &Transaction<'_>,
    signer_public_key_base64: &str,
    authorization_jti: &str,
) -> Result<PendingHandoff> {
    let row = tx
        .query_row(
            "SELECT h.signed_authorization_json, h.lease_json,
                    h.lease_digest_sha256, h.pa_reservation_id,
                    r.command_json, r.authorization_command_digest_sha256,
                    r.expires_at_epoch_s, r.action, r.security_domain,
                    r.deployment_id, r.provider, r.target_resource_id,
                    r.expected_resource_version, r.previous_fence, r.current_fence,
                    r.previous_lifecycle_revocation_epoch,
                    r.lifecycle_revocation_epoch
               FROM certificate_v2_signing_handoffs h
               JOIN certificate_v2_reservations r USING(pa_reservation_id)
              WHERE h.authorization_jti = ?
                AND h.state = 'released-pending-accept'
                AND r.state = 'reserved' AND r.lease_digest_sha256 IS NULL",
            [authorization_jti],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                ))
            },
        )
        .optional()?
        .ok_or(AdministratorError::Replay)?;
    let signed: SignedCertificateExecutionAuthorizationV2 = closed_json(&row.0)?;
    let lease: CertificateExecutionLeaseV2 = closed_json(&row.1)?;
    let command: CertificateExecutionCommandV2 = closed_json(&row.4)?;
    command
        .validate()
        .map_err(|_| AdministratorError::LedgerIntegrity)?;
    certificate_release_v2::verify_stored(signer_public_key_base64, &signed, &lease, &row.2)?;
    let target = &command.binding.target;
    let deployment = &command.binding.deployment;
    let exact = command == lease.command
        && command.certificate_digest_sha256() == row.5
        && command.jti == authorization_jti
        && command.pa_reservation_id == row.3
        && command.action.as_str() == row.7
        && deployment.security_domain == row.8
        && deployment.deployment_id == row.9
        && target.provider == row.10
        && target.target_resource_id == row.11
        && number(row.12)? == target.expected_resource_version
        && number(row.13)? == target.previous_fence
        && number(row.14)? == target.current_fence
        && number(row.15)? == target.previous_lifecycle_revocation_epoch
        && number(row.16)? == target.lifecycle_revocation_epoch;
    if !exact {
        return Err(AdministratorError::LedgerIntegrity);
    }
    Ok(PendingHandoff {
        lease,
        lease_digest_sha256: row.2,
        command_expires_at_epoch_s: number(row.6)?,
    })
}

fn closed_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| AdministratorError::LedgerIntegrity)
}

fn number(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| AdministratorError::LedgerIntegrity)
}
