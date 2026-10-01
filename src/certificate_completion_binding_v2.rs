use rusqlite::{Transaction, params};

use crate::{AdministratorError, CertificateAdministratorPolicyV2, Result};

pub(crate) fn pin(tx: &Transaction<'_>, policy: &CertificateAdministratorPolicyV2) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO certificate_v2_outcome_authority_binding
         VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
        params![
            policy.authority_outcome_issuer,
            policy.authority_outcome_audience,
            policy.certificate_authority_id,
            policy.authority_receipt_key_id,
            policy.authority_receipt_key_version,
            policy.authority_receipt_public_key_spki_sha256,
            policy.authority_receipt_key_purpose
        ],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO certificate_v2_manager_commit_binding
         VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
        params![
            policy.manager_commit_issuer,
            policy.manager_commit_audience,
            policy.manager_commit_workload,
            policy.manager_commit_key_id,
            policy.manager_commit_key_version,
            policy.manager_commit_public_key_spki_sha256,
            policy.manager_commit_key_purpose
        ],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO certificate_v2_manager_handoff_binding
         VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
        params![
            policy.manager_handoff_issuer,
            policy.manager_handoff_audience,
            policy.manager_handoff_workload,
            policy.manager_handoff_key_id,
            policy.manager_handoff_key_version,
            policy.manager_handoff_public_key_spki_sha256,
            policy.manager_handoff_key_purpose
        ],
    )?;
    if exact_authority(tx, policy)? && exact_manager(tx, policy)? && exact_handoff(tx, policy)? {
        Ok(())
    } else {
        Err(AdministratorError::LedgerIntegrity)
    }
}

fn exact_handoff(tx: &Transaction<'_>, policy: &CertificateAdministratorPolicyV2) -> Result<bool> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM certificate_v2_manager_handoff_binding
          WHERE singleton = 1 AND issuer = ? AND audience = ? AND workload = ?
            AND receipt_key_id = ? AND receipt_key_version = ?
            AND receipt_public_key_spki_sha256 = ? AND receipt_key_purpose = ?",
        params![
            policy.manager_handoff_issuer,
            policy.manager_handoff_audience,
            policy.manager_handoff_workload,
            policy.manager_handoff_key_id,
            policy.manager_handoff_key_version,
            policy.manager_handoff_public_key_spki_sha256,
            policy.manager_handoff_key_purpose
        ],
        |row| row.get(0),
    )?;
    Ok(count == 1)
}

fn exact_authority(
    tx: &Transaction<'_>,
    policy: &CertificateAdministratorPolicyV2,
) -> Result<bool> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM certificate_v2_outcome_authority_binding
          WHERE singleton = 1 AND issuer = ? AND audience = ? AND authority_id = ?
            AND receipt_key_id = ? AND receipt_key_version = ?
            AND receipt_public_key_spki_sha256 = ? AND receipt_key_purpose = ?",
        params![
            policy.authority_outcome_issuer,
            policy.authority_outcome_audience,
            policy.certificate_authority_id,
            policy.authority_receipt_key_id,
            policy.authority_receipt_key_version,
            policy.authority_receipt_public_key_spki_sha256,
            policy.authority_receipt_key_purpose
        ],
        |row| row.get(0),
    )?;
    Ok(count == 1)
}

fn exact_manager(tx: &Transaction<'_>, policy: &CertificateAdministratorPolicyV2) -> Result<bool> {
    let count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM certificate_v2_manager_commit_binding
          WHERE singleton = 1 AND issuer = ? AND audience = ? AND workload = ?
            AND commit_key_id = ? AND commit_key_version = ?
            AND commit_public_key_spki_sha256 = ? AND commit_key_purpose = ?",
        params![
            policy.manager_commit_issuer,
            policy.manager_commit_audience,
            policy.manager_commit_workload,
            policy.manager_commit_key_id,
            policy.manager_commit_key_version,
            policy.manager_commit_public_key_spki_sha256,
            policy.manager_commit_key_purpose
        ],
        |row| row.get(0),
    )?;
    Ok(count == 1)
}
