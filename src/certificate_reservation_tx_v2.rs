use rusqlite::TransactionBehavior;

use crate::{
    CertificateExecutionReservationV2, CertificatePolicyAdministratorV2,
    CertificateReservationInputV2, Result, certificate_approval_use_v2,
    certificate_authenticator_counter_v2, certificate_fence_v2, certificate_guard_v2,
    certificate_lifecycle_epoch_v2, certificate_policy_config_v2,
    certificate_reservation_write_v2::insert, certificate_revocation_v2, clock_watermark,
};

impl CertificatePolicyAdministratorV2 {
    pub(crate) fn commit_certificate_reservation(
        &mut self,
        input: &CertificateReservationInputV2<'_>,
    ) -> Result<CertificateExecutionReservationV2> {
        let command = input.command;
        let binding = &command.binding;
        let target = &binding.target;
        let deployment = &binding.deployment;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = self.clock.now();
        let now_epoch_s = crate::clock::epoch_seconds(&now)?;
        clock_watermark::advance(&transaction, &now)?;
        certificate_policy_config_v2::revalidate_freshness(input, &self.policy, now_epoch_s)?;
        certificate_revocation_v2::compare_and_swap(
            &transaction,
            &self.policy.revocation_issuer,
            &self.policy.security_domain,
            &binding.identity.pairwise_subject,
            binding.revocation.previous_identity_revocation_epoch,
            binding.revocation.snapshot_epoch,
        )?;
        certificate_guard_v2::verify_relation(&transaction, command)?;
        certificate_guard_v2::reject_unresolved_mutation(&transaction, command)?;
        let digest = insert(&transaction, input, now_epoch_s)?;
        if let Some(approval) = input.approval_evidence {
            certificate_approval_use_v2::insert(
                &transaction,
                &command.pa_reservation_id,
                approval,
            )?;
            certificate_authenticator_counter_v2::observe(&transaction, approval)?;
        }
        certificate_fence_v2::reserve(&transaction, command)?;
        certificate_lifecycle_epoch_v2::reserve(&transaction, command)?;
        transaction.commit()?;
        Ok(CertificateExecutionReservationV2 {
            authorization_jti: command.jti.clone(),
            pa_reservation_id: command.pa_reservation_id.clone(),
            action: command.action,
            security_domain: deployment.security_domain.clone(),
            deployment_id: deployment.deployment_id.clone(),
            target_resource_id: target.target_resource_id.clone(),
            current_fence: target.current_fence,
            request_digest_sha256: command.request_digest_sha256.clone(),
            authorization_command_digest_sha256: digest,
            expected_resource_version: target.expected_resource_version,
            expires_at_epoch_s: command.expires_at_epoch_s,
        })
    }
}
