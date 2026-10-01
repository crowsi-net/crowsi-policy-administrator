use rusqlite::{OptionalExtension, params};

use crate::{
    AdministratorError, CertificateLeaseSignerIdentityV2, CertificatePolicyAdministratorV2,
    CertificateSigningProgressV2, Result, certificate_execution_load_v2,
};

pub(crate) struct PreparedSigning {
    pub(crate) attempt_id: String,
    pub(crate) lease_digest_sha256: String,
    pub(crate) existing: bool,
    pub(crate) progress: CertificateSigningProgressV2,
}

pub(crate) fn load_recoverable(
    administrator: &CertificatePolicyAdministratorV2,
    authorization_jti: &str,
    signer: &CertificateLeaseSignerIdentityV2,
) -> Result<PreparedSigning> {
    certificate_execution_load_v2::verify_signer(administrator, signer)?;
    let value = load_existing(administrator, authorization_jti, signer)?
        .ok_or(AdministratorError::Replay)?;
    if matches!(
        value.progress,
        CertificateSigningProgressV2::OutcomeUnknown { .. }
    ) {
        Ok(value)
    } else {
        Err(AdministratorError::Replay)
    }
}

pub(crate) fn load_existing(
    administrator: &CertificatePolicyAdministratorV2,
    jti: &str,
    signer: &CertificateLeaseSignerIdentityV2,
) -> Result<Option<PreparedSigning>> {
    let found = administrator
        .connection
        .query_row(
            "SELECT attempt_id, lease_digest_sha256, state
              FROM certificate_v2_signing_handoffs
              WHERE authorization_jti = ? AND signer_key_id = ?
                AND signer_key_version = ?
                AND signer_public_key_digest_sha256 = ?
                AND signer_public_key_spki_sha256 = ? AND signer_workload = ?
                AND signer_purpose = ?",
            params![
                jti,
                signer.key_id,
                signer.key_version,
                signer.public_key_digest_sha256,
                signer.public_key_spki_sha256,
                signer.workload,
                signer.purpose
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    match found {
        Some((attempt, digest, state)) => match state.as_str() {
            "prepared" | "signature-unknown" => Ok(Some(prepared(attempt, digest, true, false))),
            "ready" | "released-pending-accept" | "accepted" | "not-accepted" => {
                Ok(Some(prepared(attempt, digest, true, true)))
            }
            "expired-unreleased" => Err(AdministratorError::Replay),
            _ => Err(AdministratorError::LedgerIntegrity),
        },
        None => Ok(None),
    }
}

pub(crate) fn prepared(
    attempt: String,
    digest: String,
    existing: bool,
    ready: bool,
) -> PreparedSigning {
    let progress = if ready {
        CertificateSigningProgressV2::Ready {
            attempt_id: attempt.clone(),
            lease_digest_sha256: digest.clone(),
        }
    } else {
        CertificateSigningProgressV2::OutcomeUnknown {
            attempt_id: attempt.clone(),
            lease_digest_sha256: digest.clone(),
        }
    };
    PreparedSigning {
        attempt_id: attempt,
        lease_digest_sha256: digest,
        existing,
        progress,
    }
}

pub(crate) fn ready(value: &PreparedSigning) -> CertificateSigningProgressV2 {
    CertificateSigningProgressV2::Ready {
        attempt_id: value.attempt_id.clone(),
        lease_digest_sha256: value.lease_digest_sha256.clone(),
    }
}
