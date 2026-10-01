use crowsi_control_contracts::{CertificateActionV2, CertificateOperationBindingV2};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::{AdministratorError, Result};

#[allow(clippy::too_many_lines)]
pub(crate) fn verify_relation(
    tx: &Transaction<'_>,
    command: &crowsi_control_contracts::CertificateExecutionCommandV2,
) -> Result<()> {
    let Some(related) = command.related_authorization_jti.as_deref() else {
        return if matches!(
            command.action,
            CertificateActionV2::OperationStatus | CertificateActionV2::ReconcileUnknown
        ) {
            Err(AdministratorError::Binding)
        } else {
            Ok(())
        };
    };
    let row = tx
        .query_row(
            "SELECT operation_id, action, security_domain, deployment_id, provider,
                    target_resource_id, pairwise_subject, service_id, workload,
                    profile, pa_reservation_id,
                    previous_fence, current_fence, expected_resource_version,
                    state, authorization_command_digest_sha256,
                    unknown_evidence_digest_sha256,
                    previous_lifecycle_revocation_epoch, lifecycle_revocation_epoch
               FROM certificate_v2_reservations WHERE authorization_jti = ?",
            [related],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, Option<String>>(16)?,
                    row.get::<_, i64>(17)?,
                    row.get::<_, i64>(18)?,
                ))
            },
        )
        .optional()?
        .ok_or(AdministratorError::Binding)?;
    let binding = &command.binding;
    let same_target = row.2 == binding.deployment.security_domain
        && row.3 == binding.deployment.deployment_id
        && row.4 == binding.target.provider
        && row.5 == binding.target.target_resource_id
        && row.6 == binding.identity.pairwise_subject
        && row.7 == binding.target.service_id
        && row.8 == binding.identity.workload
        && row.9 == binding.identity.requester_profile
        && u64::try_from(row.13).ok() == Some(binding.target.expected_resource_version);
    if !same_target {
        return Err(AdministratorError::Binding);
    }
    match (&command.action, binding.operation.as_ref()) {
        (
            CertificateActionV2::OperationStatus,
            Some(CertificateOperationBindingV2::OperationStatus {
                target_operation_id,
            }),
        ) if target_operation_id == &row.0
            && matches!(
                row.14.as_str(),
                "executing" | "result-unknown" | "consumed" | "reconciled"
            ) =>
        {
            Ok(())
        }
        (
            CertificateActionV2::ReconcileUnknown,
            Some(CertificateOperationBindingV2::ReconcileUnknown {
                original_action,
                target_operation_id,
                lifecycle_reservation_id,
                authority_command_digest_sha256,
                unknown_evidence_digest_sha256,
                locked_previous_fence,
                locked_current_fence,
                locked_previous_lifecycle_revocation_epoch,
                locked_lifecycle_revocation_epoch,
            }),
        ) if matches!(row.1.as_str(), "issue" | "renew" | "revoke")
            && row.14 == "result-unknown"
            && row.1 == original_action.as_str()
            && target_operation_id == &row.0
            && lifecycle_reservation_id == &row.10
            && authority_command_digest_sha256 == &row.15
            && row.16.as_ref() == Some(unknown_evidence_digest_sha256)
            && u64::try_from(row.11).ok() == Some(*locked_previous_fence)
            && u64::try_from(row.12).ok() == Some(*locked_current_fence)
            && u64::try_from(row.17).ok() == Some(*locked_previous_lifecycle_revocation_epoch)
            && u64::try_from(row.18).ok() == Some(*locked_lifecycle_revocation_epoch) =>
        {
            Ok(())
        }
        _ => Err(AdministratorError::Binding),
    }
}

pub(crate) fn reject_unresolved_mutation(
    tx: &Transaction<'_>,
    command: &crowsi_control_contracts::CertificateExecutionCommandV2,
) -> Result<()> {
    if !matches!(
        command.action,
        CertificateActionV2::Issue | CertificateActionV2::Renew | CertificateActionV2::Revoke
    ) {
        return Ok(());
    }
    let target = &command.binding.target;
    let deployment = &command.binding.deployment;
    let found = tx
        .query_row(
            "SELECT 1 FROM certificate_v2_reservations
              WHERE security_domain = ? AND deployment_id = ? AND provider = ?
                AND target_resource_id = ? AND fence_scope = 'lifecycle-mutation'
                AND state IN ('reserved', 'executing', 'result-unknown')",
            params![
                deployment.security_domain,
                deployment.deployment_id,
                target.provider,
                target.target_resource_id
            ],
            |_| Ok(()),
        )
        .optional()?;
    found.map_or(Ok(()), |()| Err(AdministratorError::OutcomeUnknown))
}
