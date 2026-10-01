use rusqlite::{ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{
    AdministratorError, CertificatePolicyAdministratorV2, Result,
    certificate_reservation_write_v2::to_i64, clock_watermark,
};

impl CertificatePolicyAdministratorV2 {
    /// Establishes the trusted local revocation watermark exactly once.
    ///
    /// # Errors
    ///
    /// Rejects malformed subjects, duplicate bootstrap, or storage failure.
    pub fn bootstrap_certificate_revocation_epoch_v2(
        &mut self,
        pairwise_subject: &str,
        epoch: u64,
    ) -> Result<()> {
        if !valid_subject(pairwise_subject) {
            return Err(AdministratorError::Trust);
        }
        let now = self.clock.now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        clock_watermark::advance(&transaction, &now)?;
        let result = transaction.execute(
            "INSERT INTO certificate_v2_revocation_epochs VALUES (?, ?, ?, ?)",
            params![
                self.policy.revocation_issuer,
                self.policy.security_domain,
                pairwise_subject,
                to_i64(epoch)?
            ],
        );
        match result {
            Ok(1) => {
                transaction.commit()?;
                Ok(())
            }
            Ok(_) => Err(AdministratorError::LedgerIntegrity),
            Err(rusqlite::Error::SqliteFailure(value, _))
                if value.code == ErrorCode::ConstraintViolation =>
            {
                Err(AdministratorError::Replay)
            }
            Err(error) => Err(AdministratorError::Storage(error)),
        }
    }
}

pub(crate) fn compare_and_swap(
    tx: &Transaction<'_>,
    issuer: &str,
    security_domain: &str,
    subject: &str,
    previous: u64,
    current: u64,
) -> Result<()> {
    let stored = tx
        .query_row(
            "SELECT epoch FROM certificate_v2_revocation_epochs
              WHERE revocation_issuer = ? AND security_domain = ?
                AND pairwise_subject = ?",
            params![issuer, security_domain, subject],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(AdministratorError::Revoked)?;
    let stored = u64::try_from(stored).map_err(|_| AdministratorError::Revoked)?;
    if current < previous || stored > current {
        return Err(AdministratorError::Revoked);
    }
    if stored == current {
        return Ok(());
    }
    if stored != previous {
        return Err(AdministratorError::Revoked);
    }
    let changed = tx.execute(
        "UPDATE certificate_v2_revocation_epochs SET epoch = ?
          WHERE revocation_issuer = ? AND security_domain = ?
            AND pairwise_subject = ? AND epoch = ?",
        params![
            to_i64(current)?,
            issuer,
            security_domain,
            subject,
            to_i64(previous)?
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(AdministratorError::Revoked)
    }
}

fn valid_subject(value: &str) -> bool {
    (8..=256).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}
