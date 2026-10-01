use crowsi_control_contracts::{CanonicalPayloadV1, EnforcementReceiptV2, Validate};
use rusqlite::{OptionalExtension, params};

use crate::{
    AdministratorError, AdministratorPolicy, ArtifactRole, KeyScope, Result, TrustedKeys,
    receipt::outcome_name, receipt_model_v2::StoredReservationV2,
};

pub(crate) fn insert(
    transaction: &rusqlite::Transaction<'_>,
    receipt: &EnforcementReceiptV2,
    digest: &str,
) -> Result<()> {
    let json = serde_json::to_string(receipt)
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO v2_signed_receipts VALUES (?, ?, ?, ?)",
            params![receipt.command_jti, receipt.receipt_id, digest, json],
        )
        .map_err(AdministratorError::Storage)?;
    Ok(())
}

pub(crate) fn matches(
    transaction: &rusqlite::Transaction<'_>,
    receipt: &EnforcementReceiptV2,
    digest: &str,
) -> Result<bool> {
    let json = serde_json::to_string(receipt)
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    Ok(transaction
        .query_row(
            "SELECT 1 FROM v2_signed_receipts
              WHERE command_jti = ? AND receipt_id = ?
                AND receipt_digest = ? AND receipt_json = ?",
            params![receipt.command_jti, receipt.receipt_id, digest, json],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(crate) fn verify_status(
    connection: &rusqlite::Connection,
    policy: &AdministratorPolicy,
    trusted_keys: &TrustedKeys,
    stored: &StoredReservationV2,
    now: &str,
) -> Result<()> {
    let terminal = matches!(
        stored.state.as_str(),
        "applied" | "rejected" | "failed" | "partial"
    );
    let row = connection
        .query_row(
            "SELECT receipt_id, receipt_digest, receipt_json
               FROM v2_signed_receipts WHERE command_jti = ?",
            [&stored.command.jti],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    if !terminal {
        return if row.is_none()
            && stored.outcome.is_none()
            && stored.receipt_id.is_none()
            && stored.receipt_digest.is_none()
        {
            Ok(())
        } else {
            Err(AdministratorError::LedgerIntegrity)
        };
    }
    let (receipt_id, digest, json) = row.ok_or(AdministratorError::LedgerIntegrity)?;
    let receipt: EnforcementReceiptV2 =
        serde_json::from_str(&json).map_err(|_| AdministratorError::LedgerIntegrity)?;
    receipt
        .validate()
        .map_err(|_| AdministratorError::LedgerIntegrity)?;
    trusted_keys.verify(
        ArtifactRole::Receipt,
        &KeyScope::Provider(policy.enforcement_audience.clone()),
        &receipt,
        &receipt.signed,
    )?;
    stored.verify(&receipt, now)?;
    let exact = stored.outcome.as_deref() == Some(stored.state.as_str())
        && stored.receipt_id.as_deref() == Some(receipt_id.as_str())
        && stored.receipt_digest.as_deref() == Some(digest.as_str())
        && receipt.receipt_id == receipt_id
        && receipt.payload_digest() == digest
        && outcome_name(receipt.outcome) == stored.state;
    if exact {
        Ok(())
    } else {
        Err(AdministratorError::LedgerIntegrity)
    }
}
