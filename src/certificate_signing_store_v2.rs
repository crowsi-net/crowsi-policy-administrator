use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{
    CertificateExecutionLeaseV2, package_signed_certificate_authorization_v2,
};
use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{
    AdministratorError, CertificateLeaseSignerOutcomeV2, CertificatePolicyAdministratorV2,
    CertificateSigningProgressV2, Result,
    certificate_signing_state_v2::{PreparedSigning, ready},
    clock_watermark,
    crypto::bare_digest_bytes,
};

pub(crate) fn store(
    administrator: &mut CertificatePolicyAdministratorV2,
    prepared: PreparedSigning,
    outcome: CertificateLeaseSignerOutcomeV2,
) -> Result<CertificateSigningProgressV2> {
    let transaction = administrator
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let now = administrator.clock.now();
    let now_epoch_s = crate::clock::epoch_seconds(&now)?;
    clock_watermark::advance(&transaction, &now)?;
    let row = transaction
        .query_row(
            "SELECT h.lease_json, h.state, r.expires_at_epoch_s
               FROM certificate_v2_signing_handoffs h
               JOIN certificate_v2_reservations r USING(pa_reservation_id)
              WHERE h.attempt_id = ? AND h.lease_digest_sha256 = ?",
            params![prepared.attempt_id, prepared.lease_digest_sha256],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(AdministratorError::Replay)?;
    if matches!(row.1.as_str(), "ready" | "released") {
        transaction.commit()?;
        return Ok(ready(&prepared));
    }
    if !matches!(row.1.as_str(), "prepared" | "signature-unknown") {
        return Err(AdministratorError::LedgerIntegrity);
    }
    match outcome {
        CertificateLeaseSignerOutcomeV2::Signed { signature_base64 } => {
            if u64::try_from(row.2)
                .ok()
                .is_none_or(|expiry| now_epoch_s >= expiry)
            {
                delete(&transaction, &prepared)?;
                transaction.commit()?;
                return Err(AdministratorError::Time);
            }
            verify_signature(
                &administrator.policy.authorization_signer_public_key_base64,
                &prepared.lease_digest_sha256,
                &signature_base64,
            )?;
            let lease: CertificateExecutionLeaseV2 =
                serde_json::from_str(&row.0).map_err(|_| AdministratorError::LedgerIntegrity)?;
            let signed = package_signed_certificate_authorization_v2(&lease, &signature_base64)
                .map_err(|error| AdministratorError::Contract(error.to_string()))?;
            let json =
                serde_json::to_string(&signed).map_err(|_| AdministratorError::LedgerIntegrity)?;
            let changed = transaction.execute(
                "UPDATE certificate_v2_signing_handoffs
                    SET signature_base64 = ?, signed_authorization_json = ?,
                        state = 'ready', signed_at_epoch_s = ?
                  WHERE attempt_id = ? AND lease_digest_sha256 = ?
                    AND state IN ('prepared', 'signature-unknown')",
                params![
                    signature_base64,
                    json,
                    i64::try_from(now_epoch_s).map_err(|_| AdministratorError::Time)?,
                    prepared.attempt_id,
                    prepared.lease_digest_sha256
                ],
            )?;
            if changed != 1 {
                return Err(AdministratorError::Replay);
            }
            transaction.commit()?;
            Ok(ready(&prepared))
        }
        CertificateLeaseSignerOutcomeV2::DefinitelyNotSigned => {
            delete(&transaction, &prepared)?;
            transaction.commit()?;
            Ok(CertificateSigningProgressV2::DefinitelyNotSigned {
                attempt_id: prepared.attempt_id,
                lease_digest_sha256: prepared.lease_digest_sha256,
            })
        }
        CertificateLeaseSignerOutcomeV2::OutcomeUnknown => {
            let changed = transaction.execute(
                "UPDATE certificate_v2_signing_handoffs SET state = 'signature-unknown'
                  WHERE attempt_id = ? AND lease_digest_sha256 = ?
                    AND state IN ('prepared', 'signature-unknown')",
                params![prepared.attempt_id, prepared.lease_digest_sha256],
            )?;
            if changed != 1 {
                return Err(AdministratorError::Replay);
            }
            transaction.commit()?;
            Ok(CertificateSigningProgressV2::OutcomeUnknown {
                attempt_id: prepared.attempt_id,
                lease_digest_sha256: prepared.lease_digest_sha256,
            })
        }
    }
}

pub(crate) fn verify_signature(public_key_base64: &str, digest: &str, encoded: &str) -> Result<()> {
    let signature = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AdministratorError::Signature)?;
    if URL_SAFE_NO_PAD.encode(&signature) != encoded {
        return Err(AdministratorError::Signature);
    }
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| AdministratorError::Signature)?;
    let public = URL_SAFE_NO_PAD
        .decode(public_key_base64)
        .map_err(|_| AdministratorError::Trust)?;
    let public: [u8; 32] = public.try_into().map_err(|_| AdministratorError::Trust)?;
    VerifyingKey::from_bytes(&public)
        .map_err(|_| AdministratorError::Trust)?
        .verify_strict(
            &bare_digest_bytes(digest)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| AdministratorError::Signature)
}

fn delete(tx: &rusqlite::Transaction<'_>, prepared: &PreparedSigning) -> Result<()> {
    let changed = tx.execute(
        "DELETE FROM certificate_v2_signing_handoffs
          WHERE attempt_id = ? AND lease_digest_sha256 = ?
            AND state IN ('prepared', 'signature-unknown')",
        params![prepared.attempt_id, prepared.lease_digest_sha256],
    )?;
    (changed == 1)
        .then_some(())
        .ok_or(AdministratorError::Replay)
}
