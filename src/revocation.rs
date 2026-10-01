use rusqlite::{OptionalExtension, Transaction, params};

use crate::{AdministratorError, Result};

pub(crate) fn reconcile(
    transaction: &Transaction<'_>,
    issuer: &str,
    pairwise_subject: &str,
    epoch: u64,
) -> Result<()> {
    let epoch = i64::try_from(epoch).map_err(|_| AdministratorError::Revoked)?;
    let stored = transaction
        .query_row(
            "SELECT revocation_epoch FROM subject_revocation_epochs
              WHERE issuer = ? AND pairwise_subject = ?",
            [issuer, pairwise_subject],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    match stored {
        Some(value) if value > epoch => Err(AdministratorError::Revoked),
        Some(value) if value < epoch => {
            let changed = transaction.execute(
                "UPDATE subject_revocation_epochs SET revocation_epoch = ?
                  WHERE issuer = ? AND pairwise_subject = ? AND revocation_epoch = ?",
                params![epoch, issuer, pairwise_subject, value],
            )?;
            if changed == 1 {
                Ok(())
            } else {
                Err(AdministratorError::Revoked)
            }
        }
        Some(_) => Ok(()),
        None => {
            transaction.execute(
                "INSERT INTO subject_revocation_epochs VALUES (?, ?, ?)",
                params![issuer, pairwise_subject, epoch],
            )?;
            Ok(())
        }
    }
}
