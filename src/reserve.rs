use crowsi_control_contracts::ControlAction;
use rusqlite::TransactionBehavior;

use crate::{
    AdministratorError, EnforcementReservation, PolicyAdministrator, ReservationInput, Result,
    clock_watermark, revocation,
};

impl PolicyAdministrator {
    /// Verifies and atomically consumes a single-use grant before a PEP runs.
    ///
    /// # Errors
    ///
    /// Rejects untrusted, denied, expired, replayed, or concurrently superseded
    /// authorization without changing a network resource.
    pub fn reserve(&mut self, input: &ReservationInput<'_>) -> Result<EnforcementReservation> {
        let now = self.clock.now();
        self.observe_time(&now)?;
        self.verify_revocation_evidence(input, &now)?;
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
        self.verify_evidence(input, &now)?;
        let policy_result = self.verify_policy(input, &now);
        let (expected, next) = checked_epochs(input)?;
        self.commit_reservation(input, &now, expected, next, policy_result)
    }
}

pub(crate) fn action_name(action: ControlAction) -> &'static str {
    match action {
        ControlAction::Quarantine => "quarantine",
        ControlAction::RestrictEgress => "restrict-egress",
        ControlAction::RevokeAccess => "revoke-access",
        ControlAction::Restore => "restore",
    }
}

pub(crate) fn channel_name(channel: crowsi_control_contracts::ControlChannel) -> &'static str {
    use crowsi_control_contracts::ControlChannel;
    match channel {
        ControlChannel::HatterInteractive => "hatter-interactive",
        ControlChannel::EmergencyConsole => "emergency-console",
        ControlChannel::ServiceAutomation => "service-automation",
    }
}

fn checked_epochs(input: &ReservationInput<'_>) -> Result<(i64, i64)> {
    let expected = to_i64(input.expected_isolation_epoch)?;
    let next = to_i64(input.next_isolation_epoch)?;
    if input.expected_isolation_epoch.checked_add(1) != Some(input.next_isolation_epoch) {
        return Err(AdministratorError::EpochConflict);
    }
    Ok((expected, next))
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| AdministratorError::EpochConflict)
}
