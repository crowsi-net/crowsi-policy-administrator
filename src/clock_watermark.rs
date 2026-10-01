use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};

use crate::{AdministratorError, PolicyAdministrator, Result, clock::valid_timestamp};

pub(crate) fn advance(transaction: &Transaction<'_>, now: &str) -> Result<()> {
    if !valid_timestamp(now) {
        return Err(AdministratorError::Time);
    }
    let stored = transaction
        .query_row(
            "SELECT observed_at FROM trusted_clock_watermark WHERE singleton = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    match stored {
        Some(value) if !valid_timestamp(&value) => Err(AdministratorError::LedgerIntegrity),
        Some(value) if now < value.as_str() => Err(AdministratorError::ClockRollback),
        Some(value) if now > value.as_str() => {
            let changed = transaction.execute(
                "UPDATE trusted_clock_watermark SET observed_at = ?
                  WHERE singleton = 1 AND observed_at = ?",
                [now, &value],
            )?;
            if changed == 1 {
                Ok(())
            } else {
                Err(AdministratorError::ClockRollback)
            }
        }
        Some(_) => Ok(()),
        None => {
            transaction.execute("INSERT INTO trusted_clock_watermark VALUES (1, ?)", [now])?;
            Ok(())
        }
    }
}

impl PolicyAdministrator {
    pub(crate) fn observe_time(&mut self, now: &str) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance(&transaction, now)?;
        transaction.commit()?;
        Ok(())
    }
}
