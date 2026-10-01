use rusqlite::{TransactionBehavior, params};

use crate::{
    AdministratorError, EnforcementStatusV2, PolicyAdministrator, Result, clock_watermark,
    port_v2::valid_digest,
};

impl PolicyAdministrator {
    /// Persists a provider call whose result cannot be proven.
    ///
    /// # Errors
    ///
    /// Rejects malformed evidence or a command not currently executing.
    pub fn mark_result_unknown_v2(
        &mut self,
        command_jti: &str,
        evidence_digest: &str,
    ) -> Result<EnforcementStatusV2> {
        if !valid_digest(evidence_digest) {
            return Err(AdministratorError::Contract(
                "unknown evidence digest is invalid".into(),
            ));
        }
        let now = self.clock.now();
        self.observe_time(&now)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        clock_watermark::advance(&transaction, &now)?;
        let changed = transaction.execute(
            "UPDATE v2_enforcement_reservations
                SET state = 'result-unknown', unknown_evidence_digest = ?
              WHERE command_jti = ? AND state = 'executing'",
            params![evidence_digest, command_jti],
        )?;
        if changed != 1 {
            return Err(AdministratorError::Replay);
        }
        transaction.commit()?;
        self.status_v2(command_jti)
    }
}
