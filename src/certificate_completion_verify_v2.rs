use crowsi_control_contracts::{CertificateExecutionCommandV2, Validate};
use rusqlite::Transaction;

use crate::{
    AdministratorError, CertificateAdministratorPolicyV2, CertificateCompletionInputV2, Result,
    TrustedKeys, certificate_completion_exact_v2,
    certificate_completion_load_v2::CompletionReservation, certificate_completion_signature_v2,
};

pub(crate) fn verify(
    tx: &Transaction<'_>,
    policy: &CertificateAdministratorPolicyV2,
    keys: &TrustedKeys,
    reservation: &CompletionReservation,
    input: &CertificateCompletionInputV2<'_>,
    now_epoch_s: u64,
) -> Result<()> {
    let authority = input.authority_evidence;
    let manager = input.manager_commit_evidence;
    authority
        .validate()
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    manager
        .validate()
        .map_err(|error| AdministratorError::Contract(error.to_string()))?;
    let command: CertificateExecutionCommandV2 = serde_json::from_str(&reservation.command_json)
        .map_err(|_| AdministratorError::LedgerIntegrity)?;
    command
        .validate()
        .map_err(|_| AdministratorError::LedgerIntegrity)?;
    if !certificate_completion_exact_v2::stored(policy, reservation, &command) {
        return Err(AdministratorError::LedgerIntegrity);
    }
    crate::certificate_execution_load_v2::verify_revocation(
        tx,
        &policy.revocation_issuer,
        &reservation.security_domain,
        &command,
    )?;
    if !certificate_completion_exact_v2::current(
        policy,
        reservation,
        &command,
        authority,
        manager,
        now_epoch_s,
    ) {
        return Err(AdministratorError::Binding);
    }
    certificate_completion_signature_v2::verify(policy, keys, authority, manager)?;
    crate::certificate_completion_relation_v2::verify(tx, reservation, &command, authority)
}
