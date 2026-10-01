use crowsi_control_contracts::CertificateActionV2;
use rusqlite::OptionalExtension;

use crate::{
    AdministratorError, CertificateExecutionStatusV2, CertificatePolicyAdministratorV2, Result,
};

impl CertificatePolicyAdministratorV2 {
    pub(crate) fn certificate_execution_status_v2(
        &self,
        authorization_jti: &str,
    ) -> Result<CertificateExecutionStatusV2> {
        self.connection
            .query_row(
                "SELECT action, target_resource_id, current_fence, state,
                        lease_digest_sha256, unknown_evidence_digest_sha256
                   FROM certificate_v2_reservations WHERE authorization_jti = ?",
                [authorization_jti],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?
            .map(|row| status(authorization_jti, row))
            .transpose()?
            .ok_or(AdministratorError::Replay)
    }
}

fn status(
    jti: &str,
    row: (String, String, i64, String, Option<String>, Option<String>),
) -> Result<CertificateExecutionStatusV2> {
    Ok(CertificateExecutionStatusV2 {
        authorization_jti: jti.into(),
        action: action(&row.0).ok_or(AdministratorError::LedgerIntegrity)?,
        target_resource_id: row.1,
        current_fence: u64::try_from(row.2).map_err(|_| AdministratorError::LedgerIntegrity)?,
        state: row.3,
        lease_digest_sha256: row.4,
        unknown_evidence_digest_sha256: row.5,
    })
}

fn action(value: &str) -> Option<CertificateActionV2> {
    [
        CertificateActionV2::Issue,
        CertificateActionV2::Renew,
        CertificateActionV2::Revoke,
        CertificateActionV2::CertificateStatus,
        CertificateActionV2::OperationStatus,
        CertificateActionV2::ReconcileUnknown,
    ]
    .into_iter()
    .find(|action| action.as_str() == value)
}
