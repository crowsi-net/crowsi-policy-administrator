#![doc = "Fail-closed Policy Administrator boundary for Crowsi."]

mod administrator;
mod certificate_abandon_v2;
mod certificate_administrator_v2;
mod certificate_approval_policy_v2;
mod certificate_approval_use_v2;
mod certificate_authenticator_counter_v2;
mod certificate_completion_binding_v2;
mod certificate_completion_exact_v2;
mod certificate_completion_inbox_load_v2;
mod certificate_completion_inbox_store_v2;
mod certificate_completion_inbox_v2;
mod certificate_completion_load_current_v2;
mod certificate_completion_load_original_v2;
mod certificate_completion_load_v2;
mod certificate_completion_orchestrator_v2;
mod certificate_completion_relation_v2;
mod certificate_completion_signature_v2;
mod certificate_completion_store_v2;
mod certificate_completion_verify_v2;
mod certificate_ddl_v2;
mod certificate_execution_load_v2;
mod certificate_execution_v2;
mod certificate_expiry_integrity_v2;
mod certificate_fence_v2;
mod certificate_guard_v2;
mod certificate_handoff_accept_v2;
mod certificate_handoff_load_v2;
mod certificate_handoff_receipt_v2;
mod certificate_handoff_transition_v2;
mod certificate_handoff_verify_v2;
mod certificate_ledger_binding_v2;
mod certificate_lifecycle_epoch_v2;
mod certificate_model_v2;
mod certificate_normalizer_v2;
mod certificate_outcome_v2;
mod certificate_policy_config_v2;
mod certificate_policy_v2;
mod certificate_release_v2;
mod certificate_reservation_tx_v2;
mod certificate_reservation_write_v2;
mod certificate_reserve_v2;
mod certificate_revocation_v2;
mod certificate_schema_completion_v2;
mod certificate_schema_security_v2;
mod certificate_schema_v2;
mod certificate_signing_expiry_v2;
mod certificate_signing_state_v2;
mod certificate_signing_store_v2;
mod certificate_signing_v2;
mod clock;
mod clock_watermark;
mod crypto;
mod error;
mod execution_v2;
mod ledger;
mod ledger_ddl;
#[cfg(unix)]
mod ledger_file;
mod ledger_schema;
mod ledger_schema_v2;
mod model;
mod model_v2;
mod persisted_receipt_v2;
mod policy_input;
mod policy_input_v2;
mod port_v2;
mod receipt;
mod receipt_model;
mod receipt_model_v2;
mod receipt_v2;
mod reservation_tx;
mod reservation_tx_v2;
mod reservation_write_v2;
mod reserve;
mod reserve_v2;
mod revocation;
mod stored_command_v2;
mod trust;
mod trust_model;
mod trust_p256;
mod trust_scope;
mod unknown_v2;
mod verify;
mod verify_revocation;
mod verify_revocation_v2;
mod verify_signatures;
mod verify_signatures_v2;
mod verify_v2;

#[cfg(test)]
macro_rules! certificate_test_modules {
    ($($module:ident),+ $(,)?) => {
        $(mod $module;)+
    };
}

#[cfg(test)]
certificate_test_modules!(
    certificate_access_tests_v2,
    certificate_completion_recovery_tests_v2,
    certificate_completion_tests_v2,
    certificate_epoch_tests_v2,
    certificate_flow_tests_v2,
    certificate_handoff_tests_v2,
    certificate_receipt_crypto_fixture_v2,
    certificate_receipt_crypto_tests_v2,
    certificate_reconcile_boundary_tests_v2,
    certificate_reconcile_tests_v2,
    certificate_signing_expiry_fixture_v2,
    certificate_signing_expiry_tests_v2,
    certificate_signing_tests_v2,
    certificate_status_v2,
    certificate_test_binding_v2,
    certificate_test_chain_v2,
    certificate_test_completion_model_v2,
    certificate_test_completion_v2,
    certificate_test_evidence_v2,
    certificate_test_handoff_v2,
    certificate_test_key_material_v2,
    certificate_test_keys_v2,
    certificate_test_policy_v2,
    certificate_test_reconciliation_v2,
    certificate_test_signatures_v2,
    certificate_test_signer_v2,
    certificate_test_trust_v2,
);

pub use administrator::PolicyAdministrator;
pub use certificate_administrator_v2::CertificatePolicyAdministratorV2;
pub use certificate_model_v2::{
    AuthenticatedCertificateManagerChannelV2, CertificateAdministratorPolicyV2,
    CertificateCompletionInputV2, CertificateCompletionReceiptV2,
    CertificateExecutionReservationV2, CertificateExecutionStatusV2, CertificateHandoffInputV2,
    CertificateHandoffReceiptAckV2, CertificateReservationInputV2,
};
pub use certificate_normalizer_v2::TargetResourceNormalizerVerifierPortV2;
pub use certificate_signing_v2::{
    CertificateLeaseSignerIdentityV2, CertificateLeaseSignerOutcomeV2, CertificateLeaseSignerV2,
    CertificateSigningProgressV2,
};
pub use clock::SimulationFixedClock;
pub use crowsi_control_contracts::{CertificateExecutionLeaseV2, PepExecutionLeaseV2};
pub use error::{AdministratorError, Result};
pub use model::{AdministratorPolicy, EnforcementReservation, EnforcementStatus, ReservationInput};
pub use model_v2::{EnforcementReservationV2, EnforcementStatusV2, ReservationInputV2};
pub use port_v2::{EnforcementPointV2, PepExecutionUncertainV2};
pub use trust::TrustedKeys;
pub use trust_model::{ArtifactRole, KeyScope};
pub use trust_p256::P256TrustAnchorV2;
