use rusqlite::{OptionalExtension, Transaction};

use crate::{AdministratorError, Result, certificate_completion_load_v2::CompletionReservation};

pub(crate) fn current(
    tx: &Transaction<'_>,
    authorization_jti: &str,
) -> Result<CompletionReservation> {
    tx.query_row(
        "SELECT authorization_jti, action, related_authorization_jti, operation_id,
                lease_digest_sha256, authorization_command_digest_sha256,
                target_resource_id, expected_resource_version,
                previous_fence, current_fence,
                previous_lifecycle_revocation_epoch, lifecycle_revocation_epoch,
                security_domain, deployment_id, provider, service_id, workload,
                pairwise_subject, profile, command_json
           FROM certificate_v2_reservations
          WHERE authorization_jti = ? AND state = 'executing'
            AND lease_digest_sha256 IS NOT NULL",
        [authorization_jti],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, String>(15)?,
                row.get::<_, String>(16)?,
                row.get::<_, String>(17)?,
                row.get::<_, String>(18)?,
                row.get::<_, String>(19)?,
            ))
        },
    )
    .optional()?
    .ok_or(AdministratorError::Replay)
    .and_then(convert)
}

type CurrentRow = (
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

fn convert(row: CurrentRow) -> Result<CompletionReservation> {
    Ok(CompletionReservation {
        authorization_jti: row.0,
        action: row.1,
        related_authorization_jti: row.2,
        operation_id: row.3,
        lease_digest_sha256: row.4,
        command_digest_sha256: row.5,
        target_resource_id: row.6,
        expected_resource_version: number(row.7)?,
        previous_fence: number(row.8)?,
        current_fence: number(row.9)?,
        previous_lifecycle_epoch: number(row.10)?,
        lifecycle_epoch: number(row.11)?,
        security_domain: row.12,
        deployment_id: row.13,
        provider: row.14,
        service_id: row.15,
        workload: row.16,
        pairwise_subject: row.17,
        profile: row.18,
        command_json: row.19,
    })
}

fn number(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| AdministratorError::LedgerIntegrity)
}
