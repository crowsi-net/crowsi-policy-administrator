use rusqlite::{OptionalExtension, Transaction};

use crate::{AdministratorError, Result, certificate_completion_load_v2::OriginalUnknown};

pub(crate) fn original(tx: &Transaction<'_>, jti: &str) -> Result<OriginalUnknown> {
    tx.query_row(
        "SELECT authorization_jti, operation_id, action, pa_reservation_id, lease_digest_sha256,
                authorization_command_digest_sha256, unknown_evidence_digest_sha256,
                previous_fence, current_fence,
                previous_lifecycle_revocation_epoch, lifecycle_revocation_epoch,
                security_domain, deployment_id, provider, target_resource_id,
                expected_resource_version, service_id, workload, pairwise_subject,
                profile, command_json
           FROM certificate_v2_reservations
          WHERE authorization_jti = ? AND state = 'result-unknown'
            AND lease_digest_sha256 IS NOT NULL
            AND unknown_evidence_digest_sha256 IS NOT NULL",
        [jti],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, i64>(15)?,
                row.get::<_, String>(16)?,
                row.get::<_, String>(17)?,
                row.get::<_, String>(18)?,
                row.get::<_, String>(19)?,
                row.get::<_, String>(20)?,
            ))
        },
    )
    .optional()?
    .ok_or(AdministratorError::Binding)
    .and_then(convert)
}

type OriginalRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    String,
    String,
    String,
    String,
    i64,
    String,
    String,
    String,
    String,
    String,
);

fn convert(row: OriginalRow) -> Result<OriginalUnknown> {
    Ok(OriginalUnknown {
        authorization_jti: row.0,
        operation_id: row.1,
        action: row.2,
        pa_reservation_id: row.3,
        lease_digest_sha256: row.4,
        command_digest_sha256: row.5,
        unknown_evidence_digest_sha256: row.6,
        previous_fence: number(row.7)?,
        current_fence: number(row.8)?,
        previous_lifecycle_epoch: number(row.9)?,
        lifecycle_epoch: number(row.10)?,
        security_domain: row.11,
        deployment_id: row.12,
        provider: row.13,
        target_resource_id: row.14,
        expected_resource_version: number(row.15)?,
        service_id: row.16,
        workload: row.17,
        pairwise_subject: row.18,
        profile: row.19,
        command_json: row.20,
    })
}

fn number(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| AdministratorError::LedgerIntegrity)
}
