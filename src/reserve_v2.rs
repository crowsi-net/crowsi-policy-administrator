use rusqlite::TransactionBehavior;

use crate::{
    EnforcementReservationV2, PolicyAdministrator, ReservationInputV2, Result, clock_watermark,
    revocation,
};

impl PolicyAdministrator {
    /// Consumes a signed V2 release reservation and advances its resource fence atomically.
    ///
    /// # Errors
    ///
    /// Rejects untrusted, replayed, stale, unresolved, or concurrently fenced commands.
    pub fn reserve_v2(
        &mut self,
        input: &ReservationInputV2<'_>,
    ) -> Result<EnforcementReservationV2> {
        let now = self.clock.now();
        self.observe_time(&now)?;
        self.verify_revocation_evidence_v2(input, &now)?;
        let epoch_transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        clock_watermark::advance(&epoch_transaction, &now)?;
        revocation::reconcile(
            &epoch_transaction,
            &input.identity.issuer,
            &input.identity.pairwise_subject,
            input.policy_information.authoritative_revocation_epoch,
        )?;
        epoch_transaction.commit()?;
        self.verify_evidence_v2(input, &now)?;
        let policy_result = self.verify_policy_v2(input, &now);
        self.commit_reservation_v2(input, &now, policy_result)
    }
}
