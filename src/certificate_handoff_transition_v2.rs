use crowsi_control_contracts::{CertificateActionV2, CertificateManagerHandoffDispositionV2};
use rusqlite::{Transaction, params};

use crate::{
    AdministratorError, CertificateHandoffInputV2, Result, certificate_fence_v2,
    certificate_handoff_load_v2, certificate_lifecycle_epoch_v2,
};

pub(crate) fn apply(
    tx: &Transaction<'_>,
    pending: &certificate_handoff_load_v2::PendingHandoff,
    input: &CertificateHandoffInputV2<'_>,
) -> Result<String> {
    match input.evidence.disposition {
        CertificateManagerHandoffDispositionV2::Accepted => accept(tx, pending, input),
        CertificateManagerHandoffDispositionV2::NotAccepted => decline(tx, pending, input),
    }
}

fn accept(
    tx: &Transaction<'_>,
    pending: &certificate_handoff_load_v2::PendingHandoff,
    input: &CertificateHandoffInputV2<'_>,
) -> Result<String> {
    certificate_fence_v2::promote(tx, &pending.lease.command)?;
    certificate_lifecycle_epoch_v2::promote(tx, &pending.lease.command)?;
    let reservation = tx.execute(
        "UPDATE certificate_v2_reservations
            SET state = 'executing', lease_digest_sha256 = ?
          WHERE authorization_jti = ? AND state = 'reserved'
            AND lease_digest_sha256 IS NULL",
        params![
            pending.lease_digest_sha256,
            input.evidence.authorization_jti
        ],
    )?;
    let handoff = tx.execute(
        "UPDATE certificate_v2_signing_handoffs SET state = 'accepted'
          WHERE authorization_jti = ? AND state = 'released-pending-accept'",
        [&input.evidence.authorization_jti],
    )?;
    exact_change(reservation, handoff)?;
    Ok("executing".into())
}

fn decline(
    tx: &Transaction<'_>,
    pending: &certificate_handoff_load_v2::PendingHandoff,
    input: &CertificateHandoffInputV2<'_>,
) -> Result<String> {
    let command = &pending.lease.command;
    let fence = certificate_fence_v2::discard(tx, command)?;
    let lifecycle = certificate_lifecycle_epoch_v2::discard(tx, command)?;
    let expected_fence = usize::from(!matches!(
        command.action,
        CertificateActionV2::CertificateStatus | CertificateActionV2::OperationStatus
    ));
    let expected_lifecycle = usize::from(command.action == CertificateActionV2::Revoke);
    if fence != expected_fence || lifecycle != expected_lifecycle {
        return Err(AdministratorError::LedgerIntegrity);
    }
    let reservation = tx.execute(
        "UPDATE certificate_v2_reservations SET state = 'abandoned'
          WHERE authorization_jti = ? AND state = 'reserved'
            AND lease_digest_sha256 IS NULL",
        [&input.evidence.authorization_jti],
    )?;
    let handoff = tx.execute(
        "UPDATE certificate_v2_signing_handoffs SET state = 'not-accepted'
          WHERE authorization_jti = ? AND state = 'released-pending-accept'",
        [&input.evidence.authorization_jti],
    )?;
    exact_change(reservation, handoff)?;
    Ok("abandoned".into())
}

fn exact_change(reservation: usize, handoff: usize) -> Result<()> {
    (reservation == 1 && handoff == 1)
        .then_some(())
        .ok_or(AdministratorError::Replay)
}
